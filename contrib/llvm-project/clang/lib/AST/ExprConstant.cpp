//===--- ExprConstant.cpp - Expression Constant Evaluator -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the Expr constant evaluator.
//
// Constant expression evaluation produces four main results:
//
//  * A success/failure flag indicating whether constant folding was successful.
//    This is the 'bool' return value used by most of the code in this file. A
//    'false' return value indicates that constant folding has failed, and any
//    appropriate diagnostic has already been produced.
//
//  * An evaluated result, valid only if constant folding has not failed.
//
//  * A flag indicating if evaluation encountered (unevaluated) side-effects.
//    These arise in cases such as (sideEffect(), 0) and (sideEffect() || 1),
//    where it is possible to determine the evaluated result regardless.
//
//  * A set of notes indicating why the evaluation was not a constant expression
//    (under the C++11 / C++1y rules only, at the moment), or, if folding failed
//    too, why the expression could not be folded.
//
// If we are checking for a potential constant expression, failure to constant
// fold a potential constant sub-expression will be indicated by a 'false'
// return value (the expression could not be folded) and no diagnostic (the
// expression is not necessarily non-constant).
//
//===----------------------------------------------------------------------===//

#include "Interp/Context.h"
#include "Interp/Frame.h"
#include "Interp/State.h"
#include "clang/AST/APValue.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/AST/ASTLambda.h"
#include "clang/AST/Attr.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/CharUnits.h"
#include "clang/AST/CurrentSourceLocExprScope.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OSLog.h"
#include "clang/AST/OptionalDiagnostic.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/TypeLoc.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/FixedPoint.h"
#include "clang/Basic/TargetInfo.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/Support/SaveAndRestore.h"
#include "llvm/Support/raw_ostream.h"
#include <cstring>
#include <functional>

#define DEBUG_TYPE "exprconstant"

using namespace clang;
using llvm::APInt;
using llvm::APSInt;
using llvm::APFloat;
using llvm::Optional;

namespace {
  struct LValue;
  class CallStackFrame;
  class EvalInfo;

  using SourceLocExprScopeGuard =
      CurrentSourceLocExprScope::SourceLocExprScopeGuard;

  static QualType getType(APValue::LValueBase B) {
    if (!B) return QualType();
    if (const ValueDecl *D = B.dyn_cast<const ValueDecl*>()) {
      // FIXME: It's unclear where we're supposed to take the type from, and
      // this actually matters for arrays of unknown bound. Eg:
      //
      // extern int arr[]; void f() { extern int arr[3]; };
      // constexpr int *p = &arr[1]; // valid?
      //
      // For now, we take the array bound from the most recent declaration.
      for (auto *Redecl = cast<ValueDecl>(D->getMostRecentDecl()); Redecl;
           Redecl = cast_or_null<ValueDecl>(Redecl->getPreviousDecl())) {
        QualType T = Redecl->getType();
        if (!T->isIncompleteArrayType())
          return T;
      }
      return D->getType();
    }

    if (B.is<TypeInfoLValue>())
      return B.getTypeInfoType();

    if (B.is<DynamicAllocLValue>())
      return B.getDynamicAllocType();

    const Expr *Base = B.get<const Expr*>();

    // For a materialized temporary, the type of the temporary we materialized
    // may not be the type of the expression.
    if (const MaterializeTemporaryExpr *MTE =
            dyn_cast<MaterializeTemporaryExpr>(Base)) {
      SmallVector<const Expr *, 2> CommaLHSs;
      SmallVector<SubobjectAdjustment, 2> Adjustments;
      const Expr *Temp = MTE->getSubExpr();
      const Expr *Inner = Temp->skipRValueSubobjectAdjustments(CommaLHSs,
                                                               Adjustments);
      // Keep any cv-qualifiers from the reference if we generated a temporary
      // for it directly. Otherwise use the type after adjustment.
      if (!Adjustments.empty())
        return Inner->getType();
    }

    return Base->getType();
  }

  /// Get an LValue path entry, which is known to not be an array index, as a
  /// field declaration.
  static const FieldDecl *getAsField(APValue::LValuePathEntry E) {
    return dyn_cast_or_null<FieldDecl>(E.getAsBaseOrMember().getPointer());
  }
  /// Get an LValue path entry, which is known to not be an array index, as a
  /// base class declaration.
  static const CXXRecordDecl *getAsBaseClass(APValue::LValuePathEntry E) {
    return dyn_cast_or_null<CXXRecordDecl>(E.getAsBaseOrMember().getPointer());
  }
  /// Determine whether this LValue path entry for a base class names a virtual
  /// base class.
  static bool isVirtualBaseClass(APValue::LValuePathEntry E) {
    return E.getAsBaseOrMember().getInt();
  }

  /// Given an expression, determine the type used to store the result of
  /// evaluating that expression.
  static QualType getStorageType(const ASTContext &Ctx, const Expr *E) {
    if (E->isRValue())
      return E->getType();
    return Ctx.getLValueReferenceType(E->getType());
  }

  /// Given a CallExpr, try to get the alloc_size attribute. May return null.
  static const AllocSizeAttr *getAllocSizeAttr(const CallExpr *CE) {
    const FunctionDecl *Callee = CE->getDirectCallee();
    return Callee ? Callee->getAttr<AllocSizeAttr>() : nullptr;
  }

  /// Attempts to unwrap a CallExpr (with an alloc_size attribute) from an Expr.
  /// This will look through a single cast.
  ///
  /// Returns null if we couldn't unwrap a function with alloc_size.
  static const CallExpr *tryUnwrapAllocSizeCall(const Expr *E) {
    if (!E->getType()->isPointerType())
      return nullptr;

    E = E->IgnoreParens();
    // If we're doing a variable assignment from e.g. malloc(N), there will
    // probably be a cast of some kind. In exotic cases, we might also see a
    // top-level ExprWithCleanups. Ignore them either way.
    if (const auto *FE = dyn_cast<FullExpr>(E))
      E = FE->getSubExpr()->IgnoreParens();

    if (const auto *Cast = dyn_cast<CastExpr>(E))
      E = Cast->getSubExpr()->IgnoreParens();

    if (const auto *CE = dyn_cast<CallExpr>(E))
      return getAllocSizeAttr(CE) ? CE : nullptr;
    return nullptr;
  }

  /// Determines whether or not the given Base contains a call to a function
  /// with the alloc_size attribute.
  static bool isBaseAnAllocSizeCall(APValue::LValueBase Base) {
    const auto *E = Base.dyn_cast<const Expr *>();
    return E && E->getType()->isPointerType() && tryUnwrapAllocSizeCall(E);
  }

  /// The bound to claim that an array of unknown bound has.
  /// The value in MostDerivedArraySize is undefined in this case. So, set it
  /// to an arbitrary value that's likely to loudly break things if it's used.
  static const uint64_t AssumedSizeForUnsizedArray =
      std::numeric_limits<uint64_t>::max() / 2;

  /// Determines if an LValue with the given LValueBase will have an unsized
  /// array in its designator.
  /// Find the path length and type of the most-derived subobject in the given
  /// path, and find the size of the containing array, if any.
  static unsigned
  findMostDerivedSubobject(ASTContext &Ctx, APValue::LValueBase Base,
                           ArrayRef<APValue::LValuePathEntry> Path,
                           uint64_t &ArraySize, QualType &Type, bool &IsArray,
                           bool &FirstEntryIsUnsizedArray) {
    // This only accepts LValueBases from APValues, and APValues don't support
    // arrays that lack size info.
    assert(!isBaseAnAllocSizeCall(Base) &&
           "Unsized arrays shouldn't appear here");
    unsigned MostDerivedLength = 0;
    Type = getType(Base);

    for (unsigned I = 0, N = Path.size(); I != N; ++I) {
      if (Type->isArrayType()) {
        const ArrayType *AT = Ctx.getAsArrayType(Type);
        Type = AT->getElementType();
        MostDerivedLength = I + 1;
        IsArray = true;

        if (auto *CAT = dyn_cast<ConstantArrayType>(AT)) {
          ArraySize = CAT->getSize().getZExtValue();
        } else {
          assert(I == 0 && "unexpected unsized array designator");
          FirstEntryIsUnsizedArray = true;
          ArraySize = AssumedSizeForUnsizedArray;
        }
      } else if (Type->isAnyComplexType()) {
        const ComplexType *CT = Type->castAs<ComplexType>();
        Type = CT->getElementType();
        ArraySize = 2;
        MostDerivedLength = I + 1;
        IsArray = true;
      } else if (const FieldDecl *FD = getAsField(Path[I])) {
        Type = FD->getType();
        ArraySize = 0;
        MostDerivedLength = I + 1;
        IsArray = false;
      } else {
        // Path[I] describes a base class.
        ArraySize = 0;
        IsArray = false;
      }
    }
    return MostDerivedLength;
  }

  /// A path from a glvalue to a subobject of that glvalue.
  struct SubobjectDesignator {
    /// True if the subobject was named in a manner not supported by C++11. Such
    /// lvalues can still be folded, but they are not core constant expressions
    /// and we cannot perform lvalue-to-rvalue conversions on them.
    unsigned Invalid : 1;

    /// Is this a pointer one past the end of an object?
    unsigned IsOnePastTheEnd : 1;

    /// Indicator of whether the first entry is an unsized array.
    unsigned FirstEntryIsAnUnsizedArray : 1;

    /// Indicator of whether the most-derived object is an array element.
    unsigned MostDerivedIsArrayElement : 1;

    /// The length of the path to the most-derived object of which this is a
    /// subobject.
    unsigned MostDerivedPathLength : 28;

    /// The size of the array of which the most-derived object is an element.
    /// This will always be 0 if the most-derived object is not an array
    /// element. 0 is not an indicator of whether or not the most-derived object
    /// is an array, however, because 0-length arrays are allowed.
    ///
    /// If the current array is an unsized array, the value of this is
    /// undefined.
    uint64_t MostDerivedArraySize;

    /// The type of the most derived object referred to by this address.
    QualType MostDerivedType;

    typedef APValue::LValuePathEntry PathEntry;

    /// The entries on the path from the glvalue to the designated subobject.
    SmallVector<PathEntry, 8> Entries;

    SubobjectDesignator() : Invalid(true) {}

    explicit SubobjectDesignator(QualType T)
        : Invalid(false), IsOnePastTheEnd(false),
          FirstEntryIsAnUnsizedArray(false), MostDerivedIsArrayElement(false),
          MostDerivedPathLength(0), MostDerivedArraySize(0),
          MostDerivedType(T) {}

    SubobjectDesignator(ASTContext &Ctx, const APValue &V)
        : Invalid(!V.isLValue() || !V.hasLValuePath()), IsOnePastTheEnd(false),
          FirstEntryIsAnUnsizedArray(false), MostDerivedIsArrayElement(false),
          MostDerivedPathLength(0), MostDerivedArraySize(0) {
      assert(V.isLValue() && "Non-LValue used to make an LValue designator?");
      if (!Invalid) {
        IsOnePastTheEnd = V.isLValueOnePastTheEnd();
        ArrayRef<PathEntry> VEntries = V.getLValuePath();
        Entries.insert(Entries.end(), VEntries.begin(), VEntries.end());
        if (V.getLValueBase()) {
          bool IsArray = false;
          bool FirstIsUnsizedArray = false;
          MostDerivedPathLength = findMostDerivedSubobject(
              Ctx, V.getLValueBase(), V.getLValuePath(), MostDerivedArraySize,
              MostDerivedType, IsArray, FirstIsUnsizedArray);
          MostDerivedIsArrayElement = IsArray;
          FirstEntryIsAnUnsizedArray = FirstIsUnsizedArray;
        }
      }
    }

    void truncate(ASTContext &Ctx, APValue::LValueBase Base,
                  unsigned NewLength) {
      if (Invalid)
        return;

      assert(Base && "cannot truncate path for null pointer");
      assert(NewLength <= Entries.size() && "not a truncation");

      if (NewLength == Entries.size())
        return;
      Entries.resize(NewLength);

      bool IsArray = false;
      bool FirstIsUnsizedArray = false;
      MostDerivedPathLength = findMostDerivedSubobject(
          Ctx, Base, Entries, MostDerivedArraySize, MostDerivedType, IsArray,
          FirstIsUnsizedArray);
      MostDerivedIsArrayElement = IsArray;
      FirstEntryIsAnUnsizedArray = FirstIsUnsizedArray;
    }

    void setInvalid() {
      Invalid = true;
      Entries.clear();
    }

    /// Determine whether the most derived subobject is an array without a
    /// known bound.
    bool isMostDerivedAnUnsizedArray() const {
      assert(!Invalid && "Calling this makes no sense on invalid designators");
      return Entries.size() == 1 && FirstEntryIsAnUnsizedArray;
    }

    /// Determine what the most derived array's size is. Results in an assertion
    /// failure if the most derived array lacks a size.
    uint64_t getMostDerivedArraySize() const {
      assert(!isMostDerivedAnUnsizedArray() && "Unsized array has no size");
      return MostDerivedArraySize;
    }

    /// Determine whether this is a one-past-the-end pointer.
    bool isOnePastTheEnd() const {
      assert(!Invalid);
      if (IsOnePastTheEnd)
        return true;
      if (!isMostDerivedAnUnsizedArray() && MostDerivedIsArrayElement &&
          Entries[MostDerivedPathLength - 1].getAsArrayIndex() ==
              MostDerivedArraySize)
        return true;
      return false;
    }

    /// Get the range of valid index adjustments in the form
    ///   {maximum value that can be subtracted from this pointer,
    ///    maximum value that can be added to this pointer}
    std::pair<uint64_t, uint64_t> validIndexAdjustments() {
      if (Invalid || isMostDerivedAnUnsizedArray())
        return {0, 0};

      // [expr.add]p4: For the purposes of these operators, a pointer to a
      // nonarray object behaves the same as a pointer to the first element of
      // an array of length one with the type of the object as its element type.
      bool IsArray = MostDerivedPathLength == Entries.size() &&
                     MostDerivedIsArrayElement;
      uint64_t ArrayIndex = IsArray ? Entries.back().getAsArrayIndex()
                                    : (uint64_t)IsOnePastTheEnd;
      uint64_t ArraySize =
          IsArray ? getMostDerivedArraySize() : (uint64_t)1;
      return {ArrayIndex, ArraySize - ArrayIndex};
    }

    /// Check that this refers to a valid subobject.
    bool isValidSubobject() const {
      if (Invalid)
        return false;
      return !isOnePastTheEnd();
    }
    /// Check that this refers to a valid subobject, and if not, produce a
    /// relevant diagnostic and set the designator as invalid.
    bool checkSubobject(EvalInfo &Info, const Expr *E, CheckSubobjectKind CSK);

    /// Get the type of the designated object.
    QualType getType(ASTContext &Ctx) const {
      assert(!Invalid && "invalid designator has no subobject type");
      return MostDerivedPathLength == Entries.size()
                 ? MostDerivedType
                 : Ctx.getRecordType(getAsBaseClass(Entries.back()));
    }

    /// Update this designator to refer to the first element within this array.
    void addArrayUnchecked(const ConstantArrayType *CAT) {
      Entries.push_back(PathEntry::ArrayIndex(0));

      // This is a most-derived object.
      MostDerivedType = CAT->getElementType();
      MostDerivedIsArrayElement = true;
      MostDerivedArraySize = CAT->getSize().getZExtValue();
      MostDerivedPathLength = Entries.size();
    }
    /// Update this designator to refer to the first element within the array of
    /// elements of type T. This is an array of unknown size.
    void addUnsizedArrayUnchecked(QualType ElemTy) {
      Entries.push_back(PathEntry::ArrayIndex(0));

      MostDerivedType = ElemTy;
      MostDerivedIsArrayElement = true;
      // The value in MostDerivedArraySize is undefined in this case. So, set it
      // to an arbitrary value that's likely to loudly break things if it's
      // used.
      MostDerivedArraySize = AssumedSizeForUnsizedArray;
      MostDerivedPathLength = Entries.size();
    }
    /// Update this designator to refer to the given base or member of this
    /// object.
    void addDeclUnchecked(const Decl *D, bool Virtual = false) {
      Entries.push_back(APValue::BaseOrMemberType(D, Virtual));

      // If this isn't a base class, it's a new most-derived object.
      if (const FieldDecl *FD = dyn_cast<FieldDecl>(D)) {
        MostDerivedType = FD->getType();
        MostDerivedIsArrayElement = false;
        MostDerivedArraySize = 0;
        MostDerivedPathLength = Entries.size();
      }
    }
    /// Update this designator to refer to the given complex component.
    void addComplexUnchecked(QualType EltTy, bool Imag) {
      Entries.push_back(PathEntry::ArrayIndex(Imag));

      // This is technically a most-derived object, though in practice this
      // is unlikely to matter.
      MostDerivedType = EltTy;
      MostDerivedIsArrayElement = true;
      MostDerivedArraySize = 2;
      MostDerivedPathLength = Entries.size();
    }
    void diagnoseUnsizedArrayPointerArithmetic(EvalInfo &Info, const Expr *E);
    void diagnosePointerArithmetic(EvalInfo &Info, const Expr *E,
                                   const APSInt &N);
    /// Add N to the address of this subobject.
    void adjustIndex(EvalInfo &Info, const Expr *E, APSInt N) {
      if (Invalid || !N) return;
      uint64_t TruncatedN = N.extOrTrunc(64).getZExtValue();
      if (isMostDerivedAnUnsizedArray()) {
        diagnoseUnsizedArrayPointerArithmetic(Info, E);
        // Can't verify -- trust that the user is doing the right thing (or if
        // not, trust that the caller will catch the bad behavior).
        // FIXME: Should we reject if this overflows, at least?
        Entries.back() = PathEntry::ArrayIndex(
            Entries.back().getAsArrayIndex() + TruncatedN);
        return;
      }

      // [expr.add]p4: For the purposes of these operators, a pointer to a
      // nonarray object behaves the same as a pointer to the first element of
      // an array of length one with the type of the object as its element type.
      bool IsArray = MostDerivedPathLength == Entries.size() &&
                     MostDerivedIsArrayElement;
      uint64_t ArrayIndex = IsArray ? Entries.back().getAsArrayIndex()
                                    : (uint64_t)IsOnePastTheEnd;
      uint64_t ArraySize =
          IsArray ? getMostDerivedArraySize() : (uint64_t)1;

      if (N < -(int64_t)ArrayIndex || N > ArraySize - ArrayIndex) {
        // Calculate the actual index in a wide enough type, so we can include
        // it in the note.
        N = N.extend(std::max<unsigned>(N.getBitWidth() + 1, 65));
        (llvm::APInt&)N += ArrayIndex;
        assert(N.ugt(ArraySize) && "bounds check failed for in-bounds index");
        diagnosePointerArithmetic(Info, E, N);
        setInvalid();
        return;
      }

      ArrayIndex += TruncatedN;
      assert(ArrayIndex <= ArraySize &&
             "bounds check succeeded for out-of-bounds index");

      if (IsArray)
        Entries.back() = PathEntry::ArrayIndex(ArrayIndex);
      else
        IsOnePastTheEnd = (ArrayIndex != 0);
    }
  };

  /// A stack frame in the constexpr call stack.
  class CallStackFrame : public interp::Frame {
  public:
    EvalInfo &Info;

    /// Parent - The caller of this stack frame.
    CallStackFrame *Caller;

    /// Callee - The function which was called.
    const FunctionDecl *Callee;

    /// This - The binding for the this pointer in this call, if any.
    const LValue *This;

    /// Arguments - Parameter bindings for this function call, indexed by
    /// parameters' function scope indices.
    APValue *Arguments;

    /// Source location information about the default argument or default
    /// initializer expression we're evaluating, if any.
    CurrentSourceLocExprScope CurSourceLocExprScope;

    // Note that we intentionally use std::map here so that references to
    // values are stable.
    typedef std::pair<const void *, unsigned> MapKeyTy;
    typedef std::map<MapKeyTy, APValue> MapTy;
    /// Temporaries - Temporary lvalues materialized within this stack frame.
    MapTy Temporaries;

    /// CallLoc - The location of the call expression for this call.
    SourceLocation CallLoc;

    /// Index - The call index of this call.
    unsigned Index;

    /// The stack of integers for tracking version numbers for temporaries.
    SmallVector<unsigned, 2> TempVersionStack = {1};
    unsigned CurTempVersion = TempVersionStack.back();

    unsigned getTempVersion() const { return TempVersionStack.back(); }

    void pushTempVersion() {
      TempVersionStack.push_back(++CurTempVersion);
    }

    void popTempVersion() {
      TempVersionStack.pop_back();
    }

    // FIXME: Adding this to every 'CallStackFrame' may have a nontrivial impact
    // on the overall stack usage of deeply-recursing constexpr evaluations.
    // (We should cache this map rather than recomputing it repeatedly.)
    // But let's try this and see how it goes; we can look into caching the map
    // as a later change.

    /// LambdaCaptureFields - Mapping from captured variables/this to
    /// corresponding data members in the closure class.
    llvm::DenseMap<const VarDecl *, FieldDecl *> LambdaCaptureFields;
    FieldDecl *LambdaThisCaptureField;

    CallStackFrame(EvalInfo &Info, SourceLocation CallLoc,
                   const FunctionDecl *Callee, const LValue *This,
                   APValue *Arguments);
    ~CallStackFrame();

    // Return the temporary for Key whose version number is Version.
    APValue *getTemporary(const void *Key, unsigned Version) {
      MapKeyTy KV(Key, Version);
      auto LB = Temporaries.lower_bound(KV);
      if (LB != Temporaries.end() && LB->first == KV)
        return &LB->second;
      // Pair (Key,Version) wasn't found in the map. Check that no elements
      // in the map have 'Key' as their key.
      assert((LB == Temporaries.end() || LB->first.first != Key) &&
             (LB == Temporaries.begin() || std::prev(LB)->first.first != Key) &&
             "Element with key 'Key' found in map");
      return nullptr;
    }

    // Return the current temporary for Key in the map.
    APValue *getCurrentTemporary(const void *Key) {
      auto UB = Temporaries.upper_bound(MapKeyTy(Key, UINT_MAX));
      if (UB != Temporaries.begin() && std::prev(UB)->first.first == Key)
        return &std::prev(UB)->second;
      return nullptr;
    }

    // Return the version number of the current temporary for Key.
    unsigned getCurrentTemporaryVersion(const void *Key) const {
      auto UB = Temporaries.upper_bound(MapKeyTy(Key, UINT_MAX));
      if (UB != Temporaries.begin() && std::prev(UB)->first.first == Key)
        return std::prev(UB)->first.second;
      return 0;
    }

    /// Allocate storage for an object of type T in this stack frame.
    /// Populates LV with a handle to the created object. Key identifies
    /// the temporary within the stack frame, and must not be reused without
    /// bumping the temporary version number.
    template<typename KeyT>
    APValue &createTemporary(const KeyT *Key, QualType T,
                             bool IsLifetimeExtended, LValue &LV);

    void describe(llvm::raw_ostream &OS) override;

    Frame *getCaller() const override { return Caller; }
    SourceLocation getCallLocation() const override { return CallLoc; }
    const FunctionDecl *getCallee() const override { return Callee; }

    bool isStdFunction() const {
      for (const DeclContext *DC = Callee; DC; DC = DC->getParent())
        if (DC->isStdNamespace())
          return true;
      return false;
    }
  };

  /// Temporarily override 'this'.
  class ThisOverrideRAII {
  public:
    ThisOverrideRAII(CallStackFrame &Frame, const LValue *NewThis, bool Enable)
        : Frame(Frame), OldThis(Frame.This) {
      if (Enable)
        Frame.This = NewThis;
    }
    ~ThisOverrideRAII() {
      Frame.This = OldThis;
    }
  private:
    CallStackFrame &Frame;
    const LValue *OldThis;
  };
}

static bool HandleDestruction(EvalInfo &Info, const Expr *E,
                              const LValue &This, QualType ThisType);
static bool HandleDestruction(EvalInfo &Info, SourceLocation Loc,
                              APValue::LValueBase LVBase, APValue &Value,
                              QualType T);

namespace {
  /// A cleanup, and a flag indicating whether it is lifetime-extended.
  class Cleanup {
    llvm::PointerIntPair<APValue*, 1, bool> Value;
    APValue::LValueBase Base;
    QualType T;

  public:
    Cleanup(APValue *Val, APValue::LValueBase Base, QualType T,
            bool IsLifetimeExtended)
        : Value(Val, IsLifetimeExtended), Base(Base), T(T) {}

    bool isLifetimeExtended() const { return Value.getInt(); }
    bool endLifetime(EvalInfo &Info, bool RunDestructors) {
      if (RunDestructors) {
        SourceLocation Loc;
        if (const ValueDecl *VD = Base.dyn_cast<const ValueDecl*>())
          Loc = VD->getLocation();
        else if (const Expr *E = Base.dyn_cast<const Expr*>())
          Loc = E->getExprLoc();
        return HandleDestruction(Info, Loc, Base, *Value.getPointer(), T);
      }
      *Value.getPointer() = APValue();
      return true;
    }

    bool hasSideEffect() {
      return T.isDestructedType();
    }
  };

  /// A reference to an object whose construction we are currently evaluating.
  struct ObjectUnderConstruction {
    APValue::LValueBase Base;
    ArrayRef<APValue::LValuePathEntry> Path;
    friend bool operator==(const ObjectUnderConstruction &LHS,
                           const ObjectUnderConstruction &RHS) {
      return LHS.Base == RHS.Base && LHS.Path == RHS.Path;
    }
    friend llvm::hash_code hash_value(const ObjectUnderConstruction &Obj) {
      return llvm::hash_combine(Obj.Base, Obj.Path);
    }
  };
  enum class ConstructionPhase {
    None,
    Bases,
    AfterBases,
    Destroying,
    DestroyingBases
  };
}

namespace llvm {
template<> struct DenseMapInfo<ObjectUnderConstruction> {
  using Base = DenseMapInfo<APValue::LValueBase>;
  static ObjectUnderConstruction getEmptyKey() {
    return {Base::getEmptyKey(), {}}; }
  static ObjectUnderConstruction getTombstoneKey() {
    return {Base::getTombstoneKey(), {}};
  }
  static unsigned getHashValue(const ObjectUnderConstruction &Object) {
    return hash_value(Object);
  }
  static bool isEqual(const ObjectUnderConstruction &LHS,
                      const ObjectUnderConstruction &RHS) {
    return LHS == RHS;
  }
};
}

namespace {
  /// A dynamically-allocated heap object.
  struct DynAlloc {
    /// The value of this heap-allocated object.
    APValue Value;
    /// The allocating expression; used for diagnostics. Either a CXXNewExpr
    /// or a CallExpr (the latter is for direct calls to operator new inside
    /// std::allocator<T>::allocate).
    const Expr *AllocExpr = nullptr;

    enum Kind {
      New,
      ArrayNew,
      StdAllocator
    };

    /// Get the kind of the allocation. This must match between allocation
    /// and deallocation.
    Kind getKind() const {
      if (auto *NE = dyn_cast<CXXNewExpr>(AllocExpr))
        return NE->isArray() ? ArrayNew : New;
      assert(isa<CallExpr>(AllocExpr));
      return StdAllocator;
    }
  };

  struct DynAllocOrder {
    bool operator()(DynamicAllocLValue L, DynamicAllocLValue R) const {
      return L.getIndex() < R.getIndex();
    }
  };

  /// EvalInfo - This is a private struct used by the evaluator to capture
  /// information about a subexpression as it is folded.  It retains information
  /// about the AST context, but also maintains information about the folded
  /// expression.
  ///
  /// If an expression could be evaluated, it is still possible it is not a C
  /// "integer constant expression" or constant expression.  If not, this struct
  /// captures information about how and why not.
  ///
  /// One bit of information passed *into* the request for constant folding
  /// indicates whether the subexpression is "evaluated" or not according to C
  /// rules.  For example, the RHS of (0 && foo()) is not evaluated.  We can
  /// evaluate the expression regardless of what the RHS is, but C only allows
  /// certain things in certain situations.
  class EvalInfo : public interp::State {
  public:
    ASTContext &Ctx;

    /// EvalStatus - Contains information about the evaluation.
    Expr::EvalStatus &EvalStatus;

    /// CurrentCall - The top of the constexpr call stack.
    CallStackFrame *CurrentCall;

    /// CallStackDepth - The number of calls in the call stack right now.
    unsigned CallStackDepth;

    /// NextCallIndex - The next call index to assign.
    unsigned NextCallIndex;

    /// StepsLeft - The remaining number of evaluation steps we're permitted
    /// to perform. This is essentially a limit for the number of statements
    /// we will evaluate.
    unsigned StepsLeft;

    /// Enable the experimental new constant interpreter. If an expression is
    /// not supported by the interpreter, an error is triggered.
    bool EnableNewConstInterp;

    /// BottomFrame - The frame in which evaluation started. This must be
    /// initialized after CurrentCall and CallStackDepth.
    CallStackFrame BottomFrame;

    /// A stack of values whose lifetimes end at the end of some surrounding
    /// evaluation frame.
    llvm::SmallVector<Cleanup, 16> CleanupStack;

    /// EvaluatingDecl - This is the declaration whose initializer is being
    /// evaluated, if any.
    APValue::LValueBase EvaluatingDecl;

    enum class EvaluatingDeclKind {
      None,
      /// We're evaluating the construction of EvaluatingDecl.
      Ctor,
      /// We're evaluating the destruction of EvaluatingDecl.
      Dtor,
    };
    EvaluatingDeclKind IsEvaluatingDecl = EvaluatingDeclKind::None;

    /// EvaluatingDeclValue - This is the value being constructed for the
    /// declaration whose initializer is being evaluated, if any.
    APValue *EvaluatingDeclValue;

    /// Set of objects that are currently being constructed.
    llvm::DenseMap<ObjectUnderConstruction, ConstructionPhase>
        ObjectsUnderConstruction;

    /// Current heap allocations, along with the location where each was
    /// allocated. We use std::map here because we need stable addresses
    /// for the stored APValues.
    std::map<DynamicAllocLValue, DynAlloc, DynAllocOrder> HeapAllocs;

    /// The number of heap allocations performed so far in this evaluation.
    unsigned NumHeapAllocs = 0;

    struct EvaluatingConstructorRAII {
      EvalInfo &EI;
      ObjectUnderConstruction Object;
      bool DidInsert;
      EvaluatingConstructorRAII(EvalInfo &EI, ObjectUnderConstruction Object,
                                bool HasBases)
          : EI(EI), Object(Object) {
        DidInsert =
            EI.ObjectsUnderConstruction
                .insert({Object, HasBases ? ConstructionPhase::Bases
                                          : ConstructionPhase::AfterBases})
                .second;
      }
      void finishedConstructingBases() {
        EI.ObjectsUnderConstruction[Object] = ConstructionPhase::AfterBases;
      }
      ~EvaluatingConstructorRAII() {
        if (DidInsert) EI.ObjectsUnderConstruction.erase(Object);
      }
    };

    struct EvaluatingDestructorRAII {
      EvalInfo &EI;
      ObjectUnderConstruction Object;
      bool DidInsert;
      EvaluatingDestructorRAII(EvalInfo &EI, ObjectUnderConstruction Object)
          : EI(EI), Object(Object) {
        DidInsert = EI.ObjectsUnderConstruction
                        .insert({Object, ConstructionPhase::Destroying})
                        .second;
      }
      void startedDestroyingBases() {
        EI.ObjectsUnderConstruction[Object] =
            ConstructionPhase::DestroyingBases;
      }
      ~EvaluatingDestructorRAII() {
        if (DidInsert)
          EI.ObjectsUnderConstruction.erase(Object);
      }
    };

    ConstructionPhase
    isEvaluatingCtorDtor(APValue::LValueBase Base,
                         ArrayRef<APValue::LValuePathEntry> Path) {
      return ObjectsUnderConstruction.lookup({Base, Path});
    }

    /// If we're currently speculatively evaluating, the outermost call stack
    /// depth at which we can mutate state, otherwise 0.
    unsigned SpeculativeEvaluationDepth = 0;

    /// The current array initialization index, if we're performing array
    /// initialization.
    uint64_t ArrayInitIndex = -1;

    /// HasActiveDiagnostic - Was the previous diagnostic stored? If so, further
    /// notes attached to it will also be stored, otherwise they will not be.
    bool HasActiveDiagnostic;

    /// Have we emitted a diagnostic explaining why we couldn't constant
    /// fold (not just why it's not strictly a constant expression)?
    bool HasFoldFailureDiagnostic;

    /// Whether or not we're in a context where the front end requires a
    /// constant value.
    bool InConstantContext;

    /// Whether we're checking that an expression is a potential constant
    /// expression. If so, do not fail on constructs that could become constant
    /// later on (such as a use of an undefined global).
    bool CheckingPotentialConstantExpression = false;

    /// Whether we're checking for an expression that has undefined behavior.
    /// If so, we will produce warnings if we encounter an operation that is
    /// always undefined.
    bool CheckingForUndefinedBehavior = false;

    enum EvaluationMode {
      /// Evaluate as a constant expression. Stop if we find that the expression
      /// is not a constant expression.
      EM_ConstantExpression,

      /// Evaluate as a constant expression. Stop if we find that the expression
      /// is not a constant expression. Some expressions can be retried in the
      /// optimizer if we don't constant fold them here, but in an unevaluated
      /// context we try to fold them immediately since the optimizer never
      /// gets a chance to look at it.
      EM_ConstantExpressionUnevaluated,

      /// Fold the expression to a constant. Stop if we hit a side-effect that
      /// we can't model.
      EM_ConstantFold,

      /// Evaluate in any way we know how. Don't worry about side-effects that
      /// can't be modeled.
      EM_IgnoreSideEffects,
    } EvalMode;

    /// Are we checking whether the expression is a potential constant
    /// expression?
    bool checkingPotentialConstantExpression() const override  {
      return CheckingPotentialConstantExpression;
    }

    /// Are we checking an expression for overflow?
    // FIXME: We should check for any kind of undefined or suspicious behavior
    // in such constructs, not just overflow.
    bool checkingForUndefinedBehavior() const override {
      return CheckingForUndefinedBehavior;
    }

    EvalInfo(const ASTContext &C, Expr::EvalStatus &S, EvaluationMode Mode)
        : Ctx(const_cast<ASTContext &>(C)), EvalStatus(S), CurrentCall(nullptr),
          CallStackDepth(0), NextCallIndex(1),
          StepsLeft(C.getLangOpts().ConstexprStepLimit),
          EnableNewConstInterp(C.getLangOpts().EnableNewConstInterp),
          BottomFrame(*this, SourceLocation(), nullptr, nullptr, nullptr),
          EvaluatingDecl((const ValueDecl *)nullptr),
          EvaluatingDeclValue(nullptr), HasActiveDiagnostic(false),
          HasFoldFailureDiagnostic(false), InConstantContext(false),
          EvalMode(Mode) {}

    ~EvalInfo() {
      discardCleanups();
    }

    void setEvaluatingDecl(APValue::LValueBase Base, APValue &Value,
                           EvaluatingDeclKind EDK = EvaluatingDeclKind::Ctor) {
      EvaluatingDecl = Base;
      IsEvaluatingDecl = EDK;
      EvaluatingDeclValue = &Value;
    }

    bool CheckCallLimit(SourceLocation Loc) {
      // Don't perform any constexpr calls (other than the call we're checking)
      // when checking a potential constant expression.
      if (checkingPotentialConstantExpression() && CallStackDepth > 1)
        return false;
      if (NextCallIndex == 0) {
        // NextCallIndex has wrapped around.
        FFDiag(Loc, diag::note_constexpr_call_limit_exceeded);
        return false;
      }
      if (CallStackDepth <= getLangOpts().ConstexprCallDepth)
        return true;
      FFDiag(Loc, diag::note_constexpr_depth_limit_exceeded)
        << getLangOpts().ConstexprCallDepth;
      return false;
    }

    std::pair<CallStackFrame *, unsigned>
    getCallFrameAndDepth(unsigned CallIndex) {
      assert(CallIndex && "no call index in getCallFrameAndDepth");
      // We will eventually hit BottomFrame, which has Index 1, so Frame can't
      // be null in this loop.
      unsigned Depth = CallStackDepth;
      CallStackFrame *Frame = CurrentCall;
      while (Frame->Index > CallIndex) {
        Frame = Frame->Caller;
        --Depth;
      }
      if (Frame->Index == CallIndex)
        return {Frame, Depth};
      return {nullptr, 0};
    }

    bool nextStep(const Stmt *S) {
      if (!StepsLeft) {
        FFDiag(S->getBeginLoc(), diag::note_constexpr_step_limit_exceeded);
        return false;
      }
      --StepsLeft;
      return true;
    }

    APValue *createHeapAlloc(const Expr *E, QualType T, LValue &LV);

    Optional<DynAlloc*> lookupDynamicAlloc(DynamicAllocLValue DA) {
      Optional<DynAlloc*> Result;
      auto It = HeapAllocs.find(DA);
      if (It != HeapAllocs.end())
        Result = &It->second;
      return Result;
    }

    /// Information about a stack frame for std::allocator<T>::[de]allocate.
    struct StdAllocatorCaller {
      unsigned FrameIndex;
      QualType ElemType;
      explicit operator bool() const { return FrameIndex != 0; };
    };

    StdAllocatorCaller getStdAllocatorCaller(StringRef FnName) const {
      for (const CallStackFrame *Call = CurrentCall; Call != &BottomFrame;
           Call = Call->Caller) {
        const auto *MD = dyn_cast_or_null<CXXMethodDecl>(Call->Callee);
        if (!MD)
          continue;
        const IdentifierInfo *FnII = MD->getIdentifier();
        if (!FnII || !FnII->isStr(FnName))
          continue;

        const auto *CTSD =
            dyn_cast<ClassTemplateSpecializationDecl>(MD->getParent());
        if (!CTSD)
          continue;

        const IdentifierInfo *ClassII = CTSD->getIdentifier();
        const TemplateArgumentList &TAL = CTSD->getTemplateArgs();
        if (CTSD->isInStdNamespace() && ClassII &&
            ClassII->isStr("allocator") && TAL.size() >= 1 &&
            TAL[0].getKind() == TemplateArgument::Type)
          return {Call->Index, TAL[0].getAsType()};
      }

      return {};
    }

    void performLifetimeExtension() {
      // Disable the cleanups for lifetime-extended temporaries.
      CleanupStack.erase(
          std::remove_if(CleanupStack.begin(), CleanupStack.end(),
                         [](Cleanup &C) { return C.isLifetimeExtended(); }),
          CleanupStack.end());
     }

    /// Throw away any remaining cleanups at the end of evaluation. If any
    /// cleanups would have had a side-effect, note that as an unmodeled
    /// side-effect and return false. Otherwise, return true.
    bool discardCleanups() {
      for (Cleanup &C : CleanupStack) {
        if (C.hasSideEffect() && !noteSideEffect()) {
          CleanupStack.clear();
          return false;
        }
      }
      CleanupStack.clear();
      return true;
    }

  private:
    interp::Frame *getCurrentFrame() override { return CurrentCall; }
    const interp::Frame *getBottomFrame() const override { return &BottomFrame; }

    bool hasActiveDiagnostic() override { return HasActiveDiagnostic; }
    void setActiveDiagnostic(bool Flag) override { HasActiveDiagnostic = Flag; }

    void setFoldFailureDiagnostic(bool Flag) override {
      HasFoldFailureDiagnostic = Flag;
    }

    Expr::EvalStatus &getEvalStatus() const override { return EvalStatus; }

    ASTContext &getCtx() const override { return Ctx; }

    // If we have a prior diagnostic, it will be noting that the expression
    // isn't a constant expression. This diagnostic is more important,
    // unless we require this evaluation to produce a constant expression.
    //
    // FIXME: We might want to show both diagnostics to the user in
    // EM_ConstantFold mode.
    bool hasPriorDiagnostic() override {
      if (!EvalStatus.Diag->empty()) {
        switch (EvalMode) {
        case EM_ConstantFold:
        case EM_IgnoreSideEffects:
          if (!HasFoldFailureDiagnostic)
            break;
          // We've already failed to fold something. Keep that diagnostic.
          LLVM_FALLTHROUGH;
        case EM_ConstantExpression:
        case EM_ConstantExpressionUnevaluated:
          setActiveDiagnostic(false);
          return true;
        }
      }
      return false;
    }

    unsigned getCallStackDepth() override { return CallStackDepth; }

  public:
    /// Should we continue evaluation after encountering a side-effect that we
    /// couldn't model?
    bool keepEvaluatingAfterSideEffect() {
      switch (EvalMode) {
      case EM_IgnoreSideEffects:
        return true;

      case EM_ConstantExpression:
      case EM_ConstantExpressionUnevaluated:
      case EM_ConstantFold:
        // By default, assume any side effect might be valid in some other
        // evaluation of this expression from a different context.
        return checkingPotentialConstantExpression() ||
               checkingForUndefinedBehavior();
      }
      llvm_unreachable("Missed EvalMode case");
    }

    /// Note that we have had a side-effect, and determine whether we should
    /// keep evaluating.
    bool noteSideEffect() {
      EvalStatus.HasSideEffects = true;
      return keepEvaluatingAfterSideEffect();
    }

    /// Should we continue evaluation after encountering undefined behavior?
    bool keepEvaluatingAfterUndefinedBehavior() {
      switch (EvalMode) {
      case EM_IgnoreSideEffects:
      case EM_ConstantFold:
        return true;

      case EM_ConstantExpression:
      case EM_ConstantExpressionUnevaluated:
        return checkingForUndefinedBehavior();
      }
      llvm_unreachable("Missed EvalMode case");
    }

    /// Note that we hit something that was technically undefined behavior, but
    /// that we can evaluate past it (such as signed overflow or floating-point
    /// division by zero.)
    bool noteUndefinedBehavior() override {
      EvalStatus.HasUndefinedBehavior = true;
      return keepEvaluatingAfterUndefinedBehavior();
    }

    /// Should we continue evaluation as much as possible after encountering a
    /// construct which can't be reduced to a value?
    bool keepEvaluatingAfterFailure() const override {
      if (!StepsLeft)
        return false;

      switch (EvalMode) {
      case EM_ConstantExpression:
      case EM_ConstantExpressionUnevaluated:
      case EM_ConstantFold:
      case EM_IgnoreSideEffects:
        return checkingPotentialConstantExpression() ||
               checkingForUndefinedBehavior();
      }
      llvm_unreachable("Missed EvalMode case");
    }

    /// Notes that we failed to evaluate an expression that other expressions
    /// directly depend on, and determine if we should keep evaluating. This
    /// should only be called if we actually intend to keep evaluating.
    ///
    /// Call noteSideEffect() instead if we may be able to ignore the value that
    /// we failed to evaluate, e.g. if we failed to evaluate Foo() in:
    ///
    /// (Foo(), 1)      // use noteSideEffect
    /// (Foo() || true) // use noteSideEffect
    /// Foo() + 1       // use noteFailure
    LLVM_NODISCARD bool noteFailure() {
      // Failure when evaluating some expression often means there is some
      // subexpression whose evaluation was skipped. Therefore, (because we
      // don't track whether we skipped an expression when unwinding after an
      // evaluation failure) every evaluation failure that bubbles up from a
      // subexpression implies that a side-effect has potentially happened. We
      // skip setting the HasSideEffects flag to true until we decide to
      // continue evaluating after that point, which happens here.
      bool KeepGoing = keepEvaluatingAfterFailure();
      EvalStatus.HasSideEffects |= KeepGoing;
      return KeepGoing;
    }

    class ArrayInitLoopIndex {
      EvalInfo &Info;
      uint64_t OuterIndex;

    public:
      ArrayInitLoopIndex(EvalInfo &Info)
          : Info(Info), OuterIndex(Info.ArrayInitIndex) {
        Info.ArrayInitIndex = 0;
      }
      ~ArrayInitLoopIndex() { Info.ArrayInitIndex = OuterIndex; }

      operator uint64_t&() { return Info.ArrayInitIndex; }
    };
  };

  /// Object used to treat all foldable expressions as constant expressions.
  struct FoldConstant {
    EvalInfo &Info;
    bool Enabled;
    bool HadNoPriorDiags;
    EvalInfo::EvaluationMode OldMode;

    explicit FoldConstant(EvalInfo &Info, bool Enabled)
      : Info(Info),
        Enabled(Enabled),
        HadNoPriorDiags(Info.EvalStatus.Diag &&
                        Info.EvalStatus.Diag->empty() &&
                        !Info.EvalStatus.HasSideEffects),
        OldMode(Info.EvalMode) {
      if (Enabled)
        Info.EvalMode = EvalInfo::EM_ConstantFold;
    }
    void keepDiagnostics() { Enabled = false; }
    ~FoldConstant() {
      if (Enabled && HadNoPriorDiags && !Info.EvalStatus.Diag->empty() &&
          !Info.EvalStatus.HasSideEffects)
        Info.EvalStatus.Diag->clear();
      Info.EvalMode = OldMode;
    }
  };

  /// RAII object used to set the current evaluation mode to ignore
  /// side-effects.
  struct IgnoreSideEffectsRAII {
    EvalInfo &Info;
    EvalInfo::EvaluationMode OldMode;
    explicit IgnoreSideEffectsRAII(EvalInfo &Info)
        : Info(Info), OldMode(Info.EvalMode) {
      Info.EvalMode = EvalInfo::EM_IgnoreSideEffects;
    }

    ~IgnoreSideEffectsRAII() { Info.EvalMode = OldMode; }
  };

  /// RAII object used to optionally suppress diagnostics and side-effects from
  /// a speculative evaluation.
  class SpeculativeEvaluationRAII {
    EvalInfo *Info = nullptr;
    Expr::EvalStatus OldStatus;
    unsigned OldSpeculativeEvaluationDepth;

    void moveFromAndCancel(SpeculativeEvaluationRAII &&Other) {
      Info = Other.Info;
      OldStatus = Other.OldStatus;
      OldSpeculativeEvaluationDepth = Other.OldSpeculativeEvaluationDepth;
      Other.Info = nullptr;
    }

    void maybeRestoreState() {
      if (!Info)
        return;

      Info->EvalStatus = OldStatus;
      Info->SpeculativeEvaluationDepth = OldSpeculativeEvaluationDepth;
    }

  public:
    SpeculativeEvaluationRAII() = default;

    SpeculativeEvaluationRAII(
        EvalInfo &Info, SmallVectorImpl<PartialDiagnosticAt> *NewDiag = nullptr)
        : Info(&Info), OldStatus(Info.EvalStatus),
          OldSpeculativeEvaluationDepth(Info.SpeculativeEvaluationDepth) {
      Info.EvalStatus.Diag = NewDiag;
      Info.SpeculativeEvaluationDepth = Info.CallStackDepth + 1;
    }

    SpeculativeEvaluationRAII(const SpeculativeEvaluationRAII &Other) = delete;
    SpeculativeEvaluationRAII(SpeculativeEvaluationRAII &&Other) {
      moveFromAndCancel(std::move(Other));
    }

    SpeculativeEvaluationRAII &operator=(SpeculativeEvaluationRAII &&Other) {
      maybeRestoreState();
      moveFromAndCancel(std::move(Other));
      return *this;
    }

    ~SpeculativeEvaluationRAII() { maybeRestoreState(); }
  };

  /// RAII object wrapping a full-expression or block scope, and handling
  /// the ending of the lifetime of temporaries created within it.
  template<bool IsFullExpression>
  class ScopeRAII {
    EvalInfo &Info;
    unsigned OldStackSize;
  public:
    ScopeRAII(EvalInfo &Info)
        : Info(Info), OldStackSize(Info.CleanupStack.size()) {
      // Push a new temporary version. This is needed to distinguish between
      // temporaries created in different iterations of a loop.
      Info.CurrentCall->pushTempVersion();
    }
    bool destroy(bool RunDestructors = true) {
      bool OK = cleanup(Info, RunDestructors, OldStackSize);
      OldStackSize = -1U;
      return OK;
    }
    ~ScopeRAII() {
      if (OldStackSize != -1U)
        destroy(false);
      // Body moved to a static method to encourage the compiler to inline away
      // instances of this class.
      Info.CurrentCall->popTempVersion();
    }
  private:
    static bool cleanup(EvalInfo &Info, bool RunDestructors,
                        unsigned OldStackSize) {
      assert(OldStackSize <= Info.CleanupStack.size() &&
             "running cleanups out of order?");

      // Run all cleanups for a block scope, and non-lifetime-extended cleanups
      // for a full-expression scope.
      bool Success = true;
      for (unsigned I = Info.CleanupStack.size(); I > OldStackSize; --I) {
        if (!(IsFullExpression &&
              Info.CleanupStack[I - 1].isLifetimeExtended())) {
          if (!Info.CleanupStack[I - 1].endLifetime(Info, RunDestructors)) {
            Success = false;
            break;
          }
        }
      }

      // Compact lifetime-extended cleanups.
      auto NewEnd = Info.CleanupStack.begin() + OldStackSize;
      if (IsFullExpression)
        NewEnd =
            std::remove_if(NewEnd, Info.CleanupStack.end(),
                           [](Cleanup &C) { return !C.isLifetimeExtended(); });
      Info.CleanupStack.erase(NewEnd, Info.CleanupStack.end());
      return Success;
    }
  };
  typedef ScopeRAII<false> BlockScopeRAII;
  typedef ScopeRAII<true> FullExpressionRAII;
}

bool SubobjectDesignator::checkSubobject(EvalInfo &Info, const Expr *E,
                                         CheckSubobjectKind CSK) {
  if (Invalid)
    return false;
  if (isOnePastTheEnd()) {
    Info.CCEDiag(E, diag::note_constexpr_past_end_subobject)
      << CSK;
    setInvalid();
    return false;
  }
  // Note, we do not diagnose if isMostDerivedAnUnsizedArray(), because there
  // must actually be at least one array element; even a VLA cannot have a
  // bound of zero. And if our index is nonzero, we already had a CCEDiag.
  return true;
}

void SubobjectDesignator::diagnoseUnsizedArrayPointerArithmetic(EvalInfo &Info,
                                                                const Expr *E) {
  Info.CCEDiag(E, diag::note_constexpr_unsized_array_indexed);
  // Do not set the designator as invalid: we can represent this situation,
  // and correct handling of __builtin_object_size requires us to do so.
}

void SubobjectDesignator::diagnosePointerArithmetic(EvalInfo &Info,
                                                    const Expr *E,
                                                    const APSInt &N) {
  // If we're complaining, we must be able to statically determine the size of
  // the most derived array.
  if (MostDerivedPathLength == Entries.size() && MostDerivedIsArrayElement)
    Info.CCEDiag(E, diag::note_constexpr_array_index)
      << N << /*array*/ 0
      << static_cast<unsigned>(getMostDerivedArraySize());
  else
    Info.CCEDiag(E, diag::note_constexpr_array_index)
      << N << /*non-array*/ 1;
  setInvalid();
}

CallStackFrame::CallStackFrame(EvalInfo &Info, SourceLocation CallLoc,
                               const FunctionDecl *Callee, const LValue *This,
                               APValue *Arguments)
    : Info(Info), Caller(Info.CurrentCall), Callee(Callee), This(This),
      Arguments(Arguments), CallLoc(CallLoc), Index(Info.NextCallIndex++) {
  Info.CurrentCall = this;
  ++Info.CallStackDepth;
}

CallStackFrame::~CallStackFrame() {
  assert(Info.CurrentCall == this && "calls retired out of order");
  --Info.CallStackDepth;
  Info.CurrentCall = Caller;
}

static bool isRead(AccessKinds AK) {
  return AK == AK_Read || AK == AK_ReadObjectRepresentation;
}

static bool isModification(AccessKinds AK) {
  switch (AK) {
  case AK_Read:
  case AK_ReadObjectRepresentation:
  case AK_MemberCall:
  case AK_DynamicCast:
  case AK_TypeId:
    return false;
  case AK_Assign:
  case AK_Increment:
  case AK_Decrement:
  case AK_Construct:
  case AK_Destroy:
    return true;
  }
  llvm_unreachable("unknown access kind");
}

static bool isAnyAccess(AccessKinds AK) {
  return isRead(AK) || isModification(AK);
}

/// Is this an access per the C++ definition?
static bool isFormalAccess(AccessKinds AK) {
  return isAnyAccess(AK) && AK != AK_Construct && AK != AK_Destroy;
}

namespace {
  struct ComplexValue {
  private:
    bool IsInt;

  public:
    APSInt IntReal, IntImag;
    APFloat FloatReal, FloatImag;

    ComplexValue() : FloatReal(APFloat::Bogus()), FloatImag(APFloat::Bogus()) {}

    void makeComplexFloat() { IsInt = false; }
    bool isComplexFloat() const { return !IsInt; }
    APFloat &getComplexFloatReal() { return FloatReal; }
    APFloat &getComplexFloatImag() { return FloatImag; }

    void makeComplexInt() { IsInt = true; }
    bool isComplexInt() const { return IsInt; }
    APSInt &getComplexIntReal() { return IntReal; }
    APSInt &getComplexIntImag() { return IntImag; }

    void moveInto(APValue &v) const {
      if (isComplexFloat())
        v = APValue(FloatReal, FloatImag);
      else
        v = APValue(IntReal, IntImag);
    }
    void setFrom(const APValue &v) {
      assert(v.isComplexFloat() || v.isComplexInt());
      if (v.isComplexFloat()) {
        makeComplexFloat();
        FloatReal = v.getComplexFloatReal();
        FloatImag = v.getComplexFloatImag();
      } else {
        makeComplexInt();
        IntReal = v.getComplexIntReal();
        IntImag = v.getComplexIntImag();
      }
    }
  };

  struct LValue {
    APValue::LValueBase Base;
    CharUnits Offset;
    SubobjectDesignator Designator;
    bool IsNullPtr : 1;
    bool InvalidBase : 1;

    const APValue::LValueBase getLValueBase() const { return Base; }
    CharUnits &getLValueOffset() { return Offset; }
    const CharUnits &getLValueOffset() const { return Offset; }
    SubobjectDesignator &getLValueDesignator() { return Designator; }
    const SubobjectDesignator &getLValueDesignator() const { return Designator;}
    bool isNullPointer() const { return IsNullPtr;}

    unsigned getLValueCallIndex() const { return Base.getCallIndex(); }
    unsigned getLValueVersion() const { return Base.getVersion(); }

    void moveInto(APValue &V) const {
      if (Designator.Invalid)
        V = APValue(Base, Offset, APValue::NoLValuePath(), IsNullPtr);
      else {
        assert(!InvalidBase && "APValues can't handle invalid LValue bases");
        V = APValue(Base, Offset, Designator.Entries,
                    Designator.IsOnePastTheEnd, IsNullPtr);
      }
    }
    void setFrom(ASTContext &Ctx, const APValue &V) {
      assert(V.isLValue() && "Setting LValue from a non-LValue?");
      Base = V.getLValueBase();
      Offset = V.getLValueOffset();
      InvalidBase = false;
      Designator = SubobjectDesignator(Ctx, V);
      IsNullPtr = V.isNullPointer();
    }

    void set(APValue::LValueBase B, bool BInvalid = false) {
#ifndef NDEBUG
      // We only allow a few types of invalid bases. Enforce that here.
      if (BInvalid) {
        const auto *E = B.get<const Expr *>();
        assert((isa<MemberExpr>(E) || tryUnwrapAllocSizeCall(E)) &&
               "Unexpected type of invalid base");
      }
#endif

      Base = B;
      Offset = CharUnits::fromQuantity(0);
      InvalidBase = BInvalid;
      Designator = SubobjectDesignator(getType(B));
      IsNullPtr = false;
    }

    void setNull(ASTContext &Ctx, QualType PointerTy) {
      Base = (Expr *)nullptr;
      Offset =
          CharUnits::fromQuantity(Ctx.getTargetNullPointerValue(PointerTy));
      InvalidBase = false;
      Designator = SubobjectDesignator(PointerTy->getPointeeType());
      IsNullPtr = true;
    }

    void setInvalid(APValue::LValueBase B, unsigned I = 0) {
      set(B, true);
    }

    std::string toString(ASTContext &Ctx, QualType T) const {
      APValue Printable;
      moveInto(Printable);
      return Printable.getAsString(Ctx, T);
    }

  private:
    // Check that this LValue is not based on a null pointer. If it is, produce
    // a diagnostic and mark the designator as invalid.
    template <typename GenDiagType>
    bool checkNullPointerDiagnosingWith(const GenDiagType &GenDiag) {
      if (Designator.Invalid)
        return false;
      if (IsNullPtr) {
        GenDiag();
        Designator.setInvalid();
        return false;
      }
      return true;
    }

  public:
    bool checkNullPointer(EvalInfo &Info, const Expr *E,
                          CheckSubobjectKind CSK) {
      return checkNullPointerDiagnosingWith([&Info, E, CSK] {
        Info.CCEDiag(E, diag::note_constexpr_null_subobject) << CSK;
      });
    }

    bool checkNullPointerForFoldAccess(EvalInfo &Info, const Expr *E,
                                       AccessKinds AK) {
      return checkNullPointerDiagnosingWith([&Info, E, AK] {
        Info.FFDiag(E, diag::note_constexpr_access_null) << AK;
      });
    }

    // Check this LValue refers to an object. If not, set the designator to be
    // invalid and emit a diagnostic.
    bool checkSubobject(EvalInfo &Info, const Expr *E, CheckSubobjectKind CSK) {
      return (CSK == CSK_ArrayToPointer || checkNullPointer(Info, E, CSK)) &&
             Designator.checkSubobject(Info, E, CSK);
    }

    void addDecl(EvalInfo &Info, const Expr *E,
                 const Decl *D, bool Virtual = false) {
      if (checkSubobject(Info, E, isa<FieldDecl>(D) ? CSK_Field : CSK_Base))
        Designator.addDeclUnchecked(D, Virtual);
    }
    void addUnsizedArray(EvalInfo &Info, const Expr *E, QualType ElemTy) {
      if (!Designator.Entries.empty()) {
        Info.CCEDiag(E, diag::note_constexpr_unsupported_unsized_array);
        Designator.setInvalid();
        return;
      }
      if (checkSubobject(Info, E, CSK_ArrayToPointer)) {
        assert(getType(Base)->isPointerType() || getType(Base)->isArrayType());
        Designator.FirstEntryIsAnUnsizedArray = true;
        Designator.addUnsizedArrayUnchecked(ElemTy);
      }
    }
    void addArray(EvalInfo &Info, const Expr *E, const ConstantArrayType *CAT) {
      if (checkSubobject(Info, E, CSK_ArrayToPointer))
        Designator.addArrayUnchecked(CAT);
    }
    void addComplex(EvalInfo &Info, const Expr *E, QualType EltTy, bool Imag) {
      if (checkSubobject(Info, E, Imag ? CSK_Imag : CSK_Real))
        Designator.addComplexUnchecked(EltTy, Imag);
    }
    void clearIsNullPointer() {
      IsNullPtr = false;
    }
    void adjustOffsetAndIndex(EvalInfo &Info, const Expr *E,
                              const APSInt &Index, CharUnits ElementSize) {
      // An index of 0 has no effect. (In C, adding 0 to a null pointer is UB,
      // but we're not required to diagnose it and it's valid in C++.)
      if (!Index)
        return;

      // Compute the new offset in the appropriate width, wrapping at 64 bits.
      // FIXME: When compiling for a 32-bit target, we should use 32-bit
      // offsets.
      uint64_t Offset64 = Offset.getQuantity();
      uint64_t ElemSize64 = ElementSize.getQuantity();
      uint64_t Index64 = Index.extOrTrunc(64).getZExtValue();
      Offset = CharUnits::fromQuantity(Offset64 + ElemSize64 * Index64);

      if (checkNullPointer(Info, E, CSK_ArrayIndex))
        Designator.adjustIndex(Info, E, Index);
      clearIsNullPointer();
    }
    void adjustOffset(CharUnits N) {
      Offset += N;
      if (N.getQuantity())
        clearIsNullPointer();
    }
  };

  struct MemberPtr {
    MemberPtr() {}
    explicit MemberPtr(const ValueDecl *Decl) :
      DeclAndIsDerivedMember(Decl, false), Path() {}

    /// The member or (direct or indirect) field referred to by this member
    /// pointer, or 0 if this is a null member pointer.
    const ValueDecl *getDecl() const {
      return DeclAndIsDerivedMember.getPointer();
    }
    /// Is this actually a member of some type derived from the relevant class?
    bool isDerivedMember() const {
      return DeclAndIsDerivedMember.getInt();
    }
    /// Get the class which the declaration actually lives in.
    const CXXRecordDecl *getContainingRecord() const {
      return cast<CXXRecordDecl>(
          DeclAndIsDerivedMember.getPointer()->getDeclContext());
    }

    void moveInto(APValue &V) const {
      V = APValue(getDecl(), isDerivedMember(), Path);
    }
    void setFrom(const APValue &V) {
      assert(V.isMemberPointer());
      DeclAndIsDerivedMember.setPointer(V.getMemberPointerDecl());
      DeclAndIsDerivedMember.setInt(V.isMemberPointerToDerivedMember());
      Path.clear();
      ArrayRef<const CXXRecordDecl*> P = V.getMemberPointerPath();
      Path.insert(Path.end(), P.begin(), P.end());
    }

    /// DeclAndIsDerivedMember - The member declaration, and a flag indicating
    /// whether the member is a member of some class derived from the class type
    /// of the member pointer.
    llvm::PointerIntPair<const ValueDecl*, 1, bool> DeclAndIsDerivedMember;
    /// Path - The path of base/derived classes from the member declaration's
    /// class (exclusive) to the class type of the member pointer (inclusive).
    SmallVector<const CXXRecordDecl*, 4> Path;

    /// Perform a cast towards the class of the Decl (either up or down the
    /// hierarchy).
    bool castBack(const CXXRecordDecl *Class) {
      assert(!Path.empty());
      const CXXRecordDecl *Expected;
      if (Path.size() >= 2)
        Expected = Path[Path.size() - 2];
      else
        Expected = getContainingRecord();
      if (Expected->getCanonicalDecl() != Class->getCanonicalDecl()) {
        // C++11 [expr.static.cast]p12: In a conversion from (D::*) to (B::*),
        // if B does not contain the original member and is not a base or
        // derived class of the class containing the original member, the result
        // of the cast is undefined.
        // C++11 [conv.mem]p2 does not cover this case for a cast from (B::*) to
        // (D::*). We consider that to be a language defect.
        return false;
      }
      Path.pop_back();
      return true;
    }
    /// Perform a base-to-derived member pointer cast.
    bool castToDerived(const CXXRecordDecl *Derived) {
      if (!getDecl())
        return true;
      if (!isDerivedMember()) {
        Path.push_back(Derived);
        return true;
      }
      if (!castBack(Derived))
        return false;
      if (Path.empty())
        DeclAndIsDerivedMember.setInt(false);
      return true;
    }
    /// Perform a derived-to-base member pointer cast.
    bool castToBase(const CXXRecordDecl *Base) {
      if (!getDecl())
        return true;
      if (Path.empty())
        DeclAndIsDerivedMember.setInt(true);
      if (isDerivedMember()) {
        Path.push_back(Base);
        return true;
      }
      return castBack(Base);
    }
  };

  /// Compare two member pointers, which are assumed to be of the same type.
  static bool operator==(const MemberPtr &LHS, const MemberPtr &RHS) {
    if (!LHS.getDecl() || !RHS.getDecl())
      return !LHS.getDecl() && !RHS.getDecl();
    if (LHS.getDecl()->getCanonicalDecl() != RHS.getDecl()->getCanonicalDecl())
      return false;
    return LHS.Path == RHS.Path;
  }
}

static bool Evaluate(APValue &Result, EvalInfo &Info, const Expr *E);
static bool EvaluateInPlace(APValue &Result, EvalInfo &Info,
                            const LValue &This, const Expr *E,
                            bool AllowNonLiteralTypes = false);
static bool EvaluateLValue(const Expr *E, LValue &Result, EvalInfo &Info,
                           bool InvalidBaseOK = false);
static bool EvaluatePointer(const Expr *E, LValue &Result, EvalInfo &Info,
                            bool InvalidBaseOK = false);
static bool EvaluateMemberPointer(const Expr *E, MemberPtr &Result,
                                  EvalInfo &Info);
static bool EvaluateTemporary(const Expr *E, LValue &Result, EvalInfo &Info);
static bool EvaluateInteger(const Expr *E, APSInt &Result, EvalInfo &Info);
static bool EvaluateIntegerOrLValue(const Expr *E, APValue &Result,
                                    EvalInfo &Info);
static bool EvaluateFloat(const Expr *E, APFloat &Result, EvalInfo &Info);
static bool EvaluateComplex(const Expr *E, ComplexValue &Res, EvalInfo &Info);
static bool EvaluateAtomic(const Expr *E, const LValue *This, APValue &Result,
                           EvalInfo &Info);
static bool EvaluateAsRValue(EvalInfo &Info, const Expr *E, APValue &Result);

/// Evaluate an integer or fixed point expression into an APResult.
static bool EvaluateFixedPointOrInteger(const Expr *E, APFixedPoint &Result,
                                        EvalInfo &Info);

/// Evaluate only a fixed point expression into an APResult.
static bool EvaluateFixedPoint(const Expr *E, APFixedPoint &Result,
                               EvalInfo &Info);

//===----------------------------------------------------------------------===//
// Misc utilities
//===----------------------------------------------------------------------===//

/// Negate an APSInt in place, converting it to a signed form if necessary, and
/// preserving its value (by extending by up to one bit as needed).
static void negateAsSigned(APSInt &Int) {
  if (Int.isUnsigned() || Int.isMinSignedValue()) {
    Int = Int.extend(Int.getBitWidth() + 1);
    Int.setIsSigned(true);
  }
  Int = -Int;
}

template<typename KeyT>
APValue &CallStackFrame::createTemporary(const KeyT *Key, QualType T,
                                         bool IsLifetimeExtended, LValue &LV) {
  unsigned Version = getTempVersion();
  APValue::LValueBase Base(Key, Index, Version);
  LV.set(Base);
  APValue &Result = Temporaries[MapKeyTy(Key, Version)];
  assert(Result.isAbsent() && "temporary created multiple times");

  // If we're creating a temporary immediately in the operand of a speculative
  // evaluation, don't register a cleanup to be run outside the speculative
  // evaluation context, since we won't actually be able to initialize this
  // object.
  if (Index <= Info.SpeculativeEvaluationDepth) {
    if (T.isDestructedType())
      Info.noteSideEffect();
  } else {
    Info.CleanupStack.push_back(Cleanup(&Result, Base, T, IsLifetimeExtended));
  }
  return Result;
}

APValue *EvalInfo::createHeapAlloc(const Expr *E, QualType T, LValue &LV) {
  if (NumHeapAllocs > DynamicAllocLValue::getMaxIndex()) {
    FFDiag(E, diag::note_constexpr_heap_alloc_limit_exceeded);
    return nullptr;
  }

  DynamicAllocLValue DA(NumHeapAllocs++);
  LV.set(APValue::LValueBase::getDynamicAlloc(DA, T));
  auto Result = HeapAllocs.emplace(std::piecewise_construct,
                                   std::forward_as_tuple(DA), std::tuple<>());
  assert(Result.second && "reused a heap alloc index?");
  Result.first->second.AllocExpr = E;
  return &Result.first->second.Value;
}

/// Produce a string describing the given constexpr call.
void CallStackFrame::describe(raw_ostream &Out) {
  unsigned ArgIndex = 0;
  bool IsMemberCall = isa<CXXMethodDecl>(Callee) &&
                      !isa<CXXConstructorDecl>(Callee) &&
                      cast<CXXMethodDecl>(Callee)->isInstance();

  if (!IsMemberCall)
    Out << *Callee << '(';

  if (This && IsMemberCall) {
    APValue Val;
    This->moveInto(Val);
    Val.printPretty(Out, Info.Ctx,
                    This->Designator.MostDerivedType);
    // FIXME: Add parens around Val if needed.
    Out << "->" << *Callee << '(';
    IsMemberCall = false;
  }

  for (FunctionDecl::param_const_iterator I = Callee->param_begin(),
       E = Callee->param_end(); I != E; ++I, ++ArgIndex) {
    if (ArgIndex > (unsigned)IsMemberCall)
      Out << ", ";

    const ParmVarDecl *Param = *I;
    const APValue &Arg = Arguments[ArgIndex];
    Arg.printPretty(Out, Info.Ctx, Param->getType());

    if (ArgIndex == 0 && IsMemberCall)
      Out << "->" << *Callee << '(';
  }

  Out << ')';
}

/// Evaluate an expression to see if it had side-effects, and discard its
/// result.
/// \return \c true if the caller should keep evaluating.
static bool EvaluateIgnoredValue(EvalInfo &Info, const Expr *E) {
  APValue Scratch;
  if (!Evaluate(Scratch, Info, E))
    // We don't need the value, but we might have skipped a side effect here.
    return Info.noteSideEffect();
  return true;
}

/// Should this call expression be treated as a string literal?
static bool IsStringLiteralCall(const CallExpr *E) {
  unsigned Builtin = E->getBuiltinCallee();
  return (Builtin == Builtin::BI__builtin___CFStringMakeConstantString ||
          Builtin == Builtin::BI__builtin___NSStringMakeConstantString);
}

static bool IsGlobalLValue(APValue::LValueBase B) {
  // C++11 [expr.const]p3 An address constant expression is a prvalue core
  // constant expression of pointer type that evaluates to...

  // ... a null pointer value, or a prvalue core constant expression of type
  // std::nullptr_t.
  if (!B) return true;

  if (const ValueDecl *D = B.dyn_cast<const ValueDecl*>()) {
    // ... the address of an object with static storage duration,
    if (const VarDecl *VD = dyn_cast<VarDecl>(D))
      return VD->hasGlobalStorage();
    // ... the address of a function,
    return isa<FunctionDecl>(D);
  }

  if (B.is<TypeInfoLValue>() || B.is<DynamicAllocLValue>())
    return true;

  const Expr *E = B.get<const Expr*>();
  switch (E->getStmtClass()) {
  default:
    return false;
  case Expr::CompoundLiteralExprClass: {
    const CompoundLiteralExpr *CLE = cast<CompoundLiteralExpr>(E);
    return CLE->isFileScope() && CLE->isLValue();
  }
  case Expr::MaterializeTemporaryExprClass:
    // A materialized temporary might have been lifetime-extended to static
    // storage duration.
    return cast<MaterializeTemporaryExpr>(E)->getStorageDuration() == SD_Static;
  // A string literal has static storage duration.
  case Expr::StringLiteralClass:
  case Expr::PredefinedExprClass:
  case Expr::ObjCStringLiteralClass:
  case Expr::ObjCEncodeExprClass:
  case Expr::CXXUuidofExprClass:
    return true;
  case Expr::ObjCBoxedExprClass:
    return cast<ObjCBoxedExpr>(E)->isExpressibleAsConstantInitializer();
  case Expr::CallExprClass:
    return IsStringLiteralCall(cast<CallExpr>(E));
  // For GCC compatibility, &&label has static storage duration.
  case Expr::AddrLabelExprClass:
    return true;
  // A Block literal expression may be used as the initialization value for
  // Block variables at global or local static scope.
  case Expr::BlockExprClass:
    return !cast<BlockExpr>(E)->getBlockDecl()->hasCaptures();
  case Expr::ImplicitValueInitExprClass:
    // FIXME:
    // We can never form an lvalue with an implicit value initialization as its
    // base through expression evaluation, so these only appear in one case: the
    // implicit variable declaration we invent when checking whether a constexpr
    // constructor can produce a constant expression. We must assume that such
    // an expression might be a global lvalue.
    return true;
  }
}

static const ValueDecl *GetLValueBaseDecl(const LValue &LVal) {
  return LVal.Base.dyn_cast<const ValueDecl*>();
}

static bool IsLiteralLValue(const LValue &Value) {
  if (Value.getLValueCallIndex())
    return false;
  const Expr *E = Value.Base.dyn_cast<const Expr*>();
  return E && !isa<MaterializeTemporaryExpr>(E);
}

static bool IsWeakLValue(const LValue &Value) {
  const ValueDecl *Decl = GetLValueBaseDecl(Value);
  return Decl && Decl->isWeak();
}

static bool isZeroSized(const LValue &Value) {
  const ValueDecl *Decl = GetLValueBaseDecl(Value);
  if (Decl && isa<VarDecl>(Decl)) {
    QualType Ty = Decl->getType();
    if (Ty->isArrayType())
      return Ty->isIncompleteType() ||
             Decl->getASTContext().getTypeSize(Ty) == 0;
  }
  return false;
}

static bool HasSameBase(const LValue &A, const LValue &B) {
  if (!A.getLValueBase())
    return !B.getLValueBase();
  if (!B.getLValueBase())
    return false;

  if (A.getLValueBase().getOpaqueValue() !=
      B.getLValueBase().getOpaqueValue()) {
    const Decl *ADecl = GetLValueBaseDecl(A);
    if (!ADecl)
      return false;
    const Decl *BDecl = GetLValueBaseDecl(B);
    if (!BDecl || ADecl->getCanonicalDecl() != BDecl->getCanonicalDecl())
      return false;
  }

  return IsGlobalLValue(A.getLValueBase()) ||
         (A.getLValueCallIndex() == B.getLValueCallIndex() &&
          A.getLValueVersion() == B.getLValueVersion());
}

static void NoteLValueLocation(EvalInfo &Info, APValue::LValueBase Base) {
  assert(Base && "no location for a null lvalue");
  const ValueDecl *VD = Base.dyn_cast<const ValueDecl*>();
  if (VD)
    Info.Note(VD->getLocation(), diag::note_declared_at);
  else if (const Expr *E = Base.dyn_cast<const Expr*>())
    Info.Note(E->getExprLoc(), diag::note_constexpr_temporary_here);
  else if (DynamicAllocLValue DA = Base.dyn_cast<DynamicAllocLValue>()) {
    // FIXME: Produce a note for dangling pointers too.
    if (Optional<DynAlloc*> Alloc = Info.lookupDynamicAlloc(DA))
      Info.Note((*Alloc)->AllocExpr->getExprLoc(),
                diag::note_constexpr_dynamic_alloc_here);
  }
  // We have no information to show for a typeid(T) object.
}

enum class CheckEvaluationResultKind {
  ConstantExpression,
  FullyInitialized,
};

/// Materialized temporaries that we've already checked to determine if they're
/// initializsed by a constant expression.
using CheckedTemporaries =
    llvm::SmallPtrSet<const MaterializeTemporaryExpr *, 8>;

static bool CheckEvaluationResult(CheckEvaluationResultKind CERK,
                                  EvalInfo &Info, SourceLocation DiagLoc,
                                  QualType Type, const APValue &Value,
                                  Expr::ConstExprUsage Usage,
                                  SourceLocation SubobjectLoc,
                                  CheckedTemporaries &CheckedTemps);

/// Check that this reference or pointer core constant expression is a valid
/// value for an address or reference constant expression. Return true if we
/// can fold this expression, whether or not it's a constant expression.
static bool CheckLValueConstantExpression(EvalInfo &Info, SourceLocation Loc,
                                          QualType Type, const LValue &LVal,
                                          Expr::ConstExprUsage Usage,
                                          CheckedTemporaries &CheckedTemps) {
  bool IsReferenceType = Type->isReferenceType();

  APValue::LValueBase Base = LVal.getLValueBase();
  const SubobjectDesignator &Designator = LVal.getLValueDesignator();

  // Check that the object is a global. Note that the fake 'this' object we
  // manufacture when checking potential constant expressions is conservatively
  // assumed to be global here.
  if (!IsGlobalLValue(Base)) {
    if (Info.getLangOpts().CPlusPlus11) {
      const ValueDecl *VD = Base.dyn_cast<const ValueDecl*>();
      Info.FFDiag(Loc, diag::note_constexpr_non_global, 1)
        << IsReferenceType << !Designator.Entries.empty()
        << !!VD << VD;
      NoteLValueLocation(Info, Base);
    } else {
      Info.FFDiag(Loc);
    }
    // Don't allow references to temporaries to escape.
    return false;
  }
  assert((Info.checkingPotentialConstantExpression() ||
          LVal.getLValueCallIndex() == 0) &&
         "have call index for global lvalue");

  if (Base.is<DynamicAllocLValue>()) {
    Info.FFDiag(Loc, diag::note_constexpr_dynamic_alloc)
        << IsReferenceType << !Designator.Entries.empty();
    NoteLValueLocation(Info, Base);
    return false;
  }

  if (const ValueDecl *VD = Base.dyn_cast<const ValueDecl*>()) {
    if (const VarDecl *Var = dyn_cast<const VarDecl>(VD)) {
      // Check if this is a thread-local variable.
      if (Var->getTLSKind())
        // FIXME: Diagnostic!
        return false;

      // A dllimport variable never acts like a constant.
      if (Usage == Expr::EvaluateForCodeGen && Var->hasAttr<DLLImportAttr>())
        // FIXME: Diagnostic!
        return false;
    }
    if (const auto *FD = dyn_cast<const FunctionDecl>(VD)) {
      // __declspec(dllimport) must be handled very carefully:
      // We must never initialize an expression with the thunk in C++.
      // Doing otherwise would allow the same id-expression to yield
      // different addresses for the same function in different translation
      // units.  However, this means that we must dynamically initialize the
      // expression with the contents of the import address table at runtime.
      //
      // The C language has no notion of ODR; furthermore, it has no notion of
      // dynamic initialization.  This means that we are permitted to
      // perform initialization with the address of the thunk.
      if (Info.getLangOpts().CPlusPlus && Usage == Expr::EvaluateForCodeGen &&
          FD->hasAttr<DLLImportAttr>())
        // FIXME: Diagnostic!
        return false;
    }
  } else if (const auto *MTE = dyn_cast_or_null<MaterializeTemporaryExpr>(
                 Base.dyn_cast<const Expr *>())) {
    if (CheckedTemps.insert(MTE).second) {
      QualType TempType = getType(Base);
      if (TempType.isDestructedType()) {
        Info.FFDiag(MTE->getExprLoc(),
                    diag::note_constexpr_unsupported_tempoarary_nontrivial_dtor)
            << TempType;
        return false;
      }

      APValue *V = MTE->getOrCreateValue(false);
      assert(V && "evasluation result refers to uninitialised temporary");
      if (!CheckEvaluationResult(CheckEvaluationResultKind::ConstantExpression,
                                 Info, MTE->getExprLoc(), TempType, *V,
                                 Usage, SourceLocation(), CheckedTemps))
        return false;
    }
  }

  // Allow address constant expressions to be past-the-end pointers. This is
  // an extension: the standard requires them to point to an object.
  if (!IsReferenceType)
    return true;

  // A reference constant expression must refer to an object.
  if (!Base) {
    // FIXME: diagnostic
    Info.CCEDiag(Loc);
    return true;
  }

  // Does this refer one past the end of some object?
  if (!Designator.Invalid && Designator.isOnePastTheEnd()) {
    const ValueDecl *VD = Base.dyn_cast<const ValueDecl*>();
    Info.FFDiag(Loc, diag::note_constexpr_past_end, 1)
      << !Designator.Entries.empty() << !!VD << VD;
    NoteLValueLocation(Info, Base);
  }

  return true;
}

/// Member pointers are constant expressions unless they point to a
/// non-virtual dllimport member function.
static bool CheckMemberPointerConstantExpression(EvalInfo &Info,
                                                 SourceLocation Loc,
                                                 QualType Type,
                                                 const APValue &Value,
                                                 Expr::ConstExprUsage Usage) {
  const ValueDecl *Member = Value.getMemberPointerDecl();
  const auto *FD = dyn_cast_or_null<CXXMethodDecl>(Member);
  if (!FD)
    return true;
  return Usage == Expr::EvaluateForMangling || FD->isVirtual() ||
         !FD->hasAttr<DLLImportAttr>();
}

/// Check that this core constant expression is of literal type, and if not,
/// produce an appropriate diagnostic.
static bool CheckLiteralType(EvalInfo &Info, const Expr *E,
                             const LValue *This = nullptr) {
  if (!E->isRValue() || E->getType()->isLiteralType(Info.Ctx))
    return true;

  // C++1y: A constant initializer for an object o [...] may also invoke
  // constexpr constructors for o and its subobjects even if those objects
  // are of non-literal class types.
  //
  // C++11 missed this detail for aggregates, so classes like this:
  //   struct foo_t { union { int i; volatile int j; } u; };
  // are not (obviously) initializable like so:
  //   __attribute__((__require_constant_initialization__))
  //   static const foo_t x = {{0}};
  // because "i" is a subobject with non-literal initialization (due to the
  // volatile member of the union). See:
  //   http://www.open-std.org/jtc1/sc22/wg21/docs/cwg_active.html#1677
  // Therefore, we use the C++1y behavior.
  if (This && Info.EvaluatingDecl == This->getLValueBase())
    return true;

  // Prvalue constant expressions must be of literal types.
  if (Info.getLangOpts().CPlusPlus11)
    Info.FFDiag(E, diag::note_constexpr_nonliteral)
      << E->getType();
  else
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
  return false;
}

static bool CheckEvaluationResult(CheckEvaluationResultKind CERK,
                                  EvalInfo &Info, SourceLocation DiagLoc,
                                  QualType Type, const APValue &Value,
                                  Expr::ConstExprUsage Usage,
                                  SourceLocation SubobjectLoc,
                                  CheckedTemporaries &CheckedTemps) {
  if (!Value.hasValue()) {
    Info.FFDiag(DiagLoc, diag::note_constexpr_uninitialized)
      << true << Type;
    if (SubobjectLoc.isValid())
      Info.Note(SubobjectLoc, diag::note_constexpr_subobject_declared_here);
    return false;
  }

  // We allow _Atomic(T) to be initialized from anything that T can be
  // initialized from.
  if (const AtomicType *AT = Type->getAs<AtomicType>())
    Type = AT->getValueType();

  // Core issue 1454: For a literal constant expression of array or class type,
  // each subobject of its value shall have been initialized by a constant
  // expression.
  if (Value.isArray()) {
    QualType EltTy = Type->castAsArrayTypeUnsafe()->getElementType();
    for (unsigned I = 0, N = Value.getArrayInitializedElts(); I != N; ++I) {
      if (!CheckEvaluationResult(CERK, Info, DiagLoc, EltTy,
                                 Value.getArrayInitializedElt(I), Usage,
                                 SubobjectLoc, CheckedTemps))
        return false;
    }
    if (!Value.hasArrayFiller())
      return true;
    return CheckEvaluationResult(CERK, Info, DiagLoc, EltTy,
                                 Value.getArrayFiller(), Usage, SubobjectLoc,
                                 CheckedTemps);
  }
  if (Value.isUnion() && Value.getUnionField()) {
    return CheckEvaluationResult(
        CERK, Info, DiagLoc, Value.getUnionField()->getType(),
        Value.getUnionValue(), Usage, Value.getUnionField()->getLocation(),
        CheckedTemps);
  }
  if (Value.isStruct()) {
    RecordDecl *RD = Type->castAs<RecordType>()->getDecl();
    if (const CXXRecordDecl *CD = dyn_cast<CXXRecordDecl>(RD)) {
      unsigned BaseIndex = 0;
      for (const CXXBaseSpecifier &BS : CD->bases()) {
        if (!CheckEvaluationResult(CERK, Info, DiagLoc, BS.getType(),
                                   Value.getStructBase(BaseIndex), Usage,
                                   BS.getBeginLoc(), CheckedTemps))
          return false;
        ++BaseIndex;
      }
    }
    for (const auto *I : RD->fields()) {
      if (I->isUnnamedBitfield())
        continue;

      if (!CheckEvaluationResult(CERK, Info, DiagLoc, I->getType(),
                                 Value.getStructField(I->getFieldIndex()),
                                 Usage, I->getLocation(), CheckedTemps))
        return false;
    }
  }

  if (Value.isLValue() &&
      CERK == CheckEvaluationResultKind::ConstantExpression) {
    LValue LVal;
    LVal.setFrom(Info.Ctx, Value);
    return CheckLValueConstantExpression(Info, DiagLoc, Type, LVal, Usage,
                                         CheckedTemps);
  }

  if (Value.isMemberPointer() &&
      CERK == CheckEvaluationResultKind::ConstantExpression)
    return CheckMemberPointerConstantExpression(Info, DiagLoc, Type, Value, Usage);

  // Everything else is fine.
  return true;
}

/// Check that this core constant expression value is a valid value for a
/// constant expression. If not, report an appropriate diagnostic. Does not
/// check that the expression is of literal type.
static bool
CheckConstantExpression(EvalInfo &Info, SourceLocation DiagLoc, QualType Type,
                        const APValue &Value,
                        Expr::ConstExprUsage Usage = Expr::EvaluateForCodeGen) {
  CheckedTemporaries CheckedTemps;
  return CheckEvaluationResult(CheckEvaluationResultKind::ConstantExpression,
                               Info, DiagLoc, Type, Value, Usage,
                               SourceLocation(), CheckedTemps);
}

/// Check that this evaluated value is fully-initialized and can be loaded by
/// an lvalue-to-rvalue conversion.
static bool CheckFullyInitialized(EvalInfo &Info, SourceLocation DiagLoc,
                                  QualType Type, const APValue &Value) {
  CheckedTemporaries CheckedTemps;
  return CheckEvaluationResult(
      CheckEvaluationResultKind::FullyInitialized, Info, DiagLoc, Type, Value,
      Expr::EvaluateForCodeGen, SourceLocation(), CheckedTemps);
}

/// Enforce C++2a [expr.const]/4.17, which disallows new-expressions unless
/// "the allocated storage is deallocated within the evaluation".
static bool CheckMemoryLeaks(EvalInfo &Info) {
  if (!Info.HeapAllocs.empty()) {
    // We can still fold to a constant despite a compile-time memory leak,
    // so long as the heap allocation isn't referenced in the result (we check
    // that in CheckConstantExpression).
    Info.CCEDiag(Info.HeapAllocs.begin()->second.AllocExpr,
                 diag::note_constexpr_memory_leak)
        << unsigned(Info.HeapAllocs.size() - 1);
  }
  return true;
}

static bool EvalPointerValueAsBool(const APValue &Value, bool &Result) {
  // A null base expression indicates a null pointer.  These are always
  // evaluatable, and they are false unless the offset is zero.
  if (!Value.getLValueBase()) {
    Result = !Value.getLValueOffset().isZero();
    return true;
  }

  // We have a non-null base.  These are generally known to be true, but if it's
  // a weak declaration it can be null at runtime.
  Result = true;
  const ValueDecl *Decl = Value.getLValueBase().dyn_cast<const ValueDecl*>();
  return !Decl || !Decl->isWeak();
}

static bool HandleConversionToBool(const APValue &Val, bool &Result) {
  switch (Val.getKind()) {
  case APValue::None:
  case APValue::Indeterminate:
    return false;
  case APValue::Int:
    Result = Val.getInt().getBoolValue();
    return true;
  case APValue::FixedPoint:
    Result = Val.getFixedPoint().getBoolValue();
    return true;
  case APValue::Float:
    Result = !Val.getFloat().isZero();
    return true;
  case APValue::ComplexInt:
    Result = Val.getComplexIntReal().getBoolValue() ||
             Val.getComplexIntImag().getBoolValue();
    return true;
  case APValue::ComplexFloat:
    Result = !Val.getComplexFloatReal().isZero() ||
             !Val.getComplexFloatImag().isZero();
    return true;
  case APValue::LValue:
    return EvalPointerValueAsBool(Val, Result);
  case APValue::MemberPointer:
    Result = Val.getMemberPointerDecl();
    return true;
  case APValue::Vector:
  case APValue::Array:
  case APValue::Struct:
  case APValue::Union:
  case APValue::AddrLabelDiff:
    return false;
  }

  llvm_unreachable("unknown APValue kind");
}

static bool EvaluateAsBooleanCondition(const Expr *E, bool &Result,
                                       EvalInfo &Info) {
  assert(E->isRValue() && "missing lvalue-to-rvalue conv in bool condition");
  APValue Val;
  if (!Evaluate(Val, Info, E))
    return false;
  return HandleConversionToBool(Val, Result);
}

template<typename T>
static bool HandleOverflow(EvalInfo &Info, const Expr *E,
                           const T &SrcValue, QualType DestType) {
  Info.CCEDiag(E, diag::note_constexpr_overflow)
    << SrcValue << DestType;
  return Info.noteUndefinedBehavior();
}

static bool HandleFloatToIntCast(EvalInfo &Info, const Expr *E,
                                 QualType SrcType, const APFloat &Value,
                                 QualType DestType, APSInt &Result) {
  unsigned DestWidth = Info.Ctx.getIntWidth(DestType);
  // Determine whether we are converting to unsigned or signed.
  bool DestSigned = DestType->isSignedIntegerOrEnumerationType();

  Result = APSInt(DestWidth, !DestSigned);
  bool ignored;
  if (Value.convertToInteger(Result, llvm::APFloat::rmTowardZero, &ignored)
      & APFloat::opInvalidOp)
    return HandleOverflow(Info, E, Value, DestType);
  return true;
}

static bool HandleFloatToFloatCast(EvalInfo &Info, const Expr *E,
                                   QualType SrcType, QualType DestType,
                                   APFloat &Result) {
  APFloat Value = Result;
  bool ignored;
  Result.convert(Info.Ctx.getFloatTypeSemantics(DestType),
                 APFloat::rmNearestTiesToEven, &ignored);
  return true;
}

static APSInt HandleIntToIntCast(EvalInfo &Info, const Expr *E,
                                 QualType DestType, QualType SrcType,
                                 const APSInt &Value) {
  unsigned DestWidth = Info.Ctx.getIntWidth(DestType);
  // Figure out if this is a truncate, extend or noop cast.
  // If the input is signed, do a sign extend, noop, or truncate.
  APSInt Result = Value.extOrTrunc(DestWidth);
  Result.setIsUnsigned(DestType->isUnsignedIntegerOrEnumerationType());
  if (DestType->isBooleanType())
    Result = Value.getBoolValue();
  return Result;
}

static bool HandleIntToFloatCast(EvalInfo &Info, const Expr *E,
                                 QualType SrcType, const APSInt &Value,
                                 QualType DestType, APFloat &Result) {
  Result = APFloat(Info.Ctx.getFloatTypeSemantics(DestType), 1);
  Result.convertFromAPInt(Value, Value.isSigned(),
                          APFloat::rmNearestTiesToEven);
  return true;
}

static bool truncateBitfieldValue(EvalInfo &Info, const Expr *E,
                                  APValue &Value, const FieldDecl *FD) {
  assert(FD->isBitField() && "truncateBitfieldValue on non-bitfield");

  if (!Value.isInt()) {
    // Trying to store a pointer-cast-to-integer into a bitfield.
    // FIXME: In this case, we should provide the diagnostic for casting
    // a pointer to an integer.
    assert(Value.isLValue() && "integral value neither int nor lvalue?");
    Info.FFDiag(E);
    return false;
  }

  APSInt &Int = Value.getInt();
  unsigned OldBitWidth = Int.getBitWidth();
  unsigned NewBitWidth = FD->getBitWidthValue(Info.Ctx);
  if (NewBitWidth < OldBitWidth)
    Int = Int.trunc(NewBitWidth).extend(OldBitWidth);
  return true;
}

static bool EvalAndBitcastToAPInt(EvalInfo &Info, const Expr *E,
                                  llvm::APInt &Res) {
  APValue SVal;
  if (!Evaluate(SVal, Info, E))
    return false;
  if (SVal.isInt()) {
    Res = SVal.getInt();
    return true;
  }
  if (SVal.isFloat()) {
    Res = SVal.getFloat().bitcastToAPInt();
    return true;
  }
  if (SVal.isVector()) {
    QualType VecTy = E->getType();
    unsigned VecSize = Info.Ctx.getTypeSize(VecTy);
    QualType EltTy = VecTy->castAs<VectorType>()->getElementType();
    unsigned EltSize = Info.Ctx.getTypeSize(EltTy);
    bool BigEndian = Info.Ctx.getTargetInfo().isBigEndian();
    Res = llvm::APInt::getNullValue(VecSize);
    for (unsigned i = 0; i < SVal.getVectorLength(); i++) {
      APValue &Elt = SVal.getVectorElt(i);
      llvm::APInt EltAsInt;
      if (Elt.isInt()) {
        EltAsInt = Elt.getInt();
      } else if (Elt.isFloat()) {
        EltAsInt = Elt.getFloat().bitcastToAPInt();
      } else {
        // Don't try to handle vectors of anything other than int or float
        // (not sure if it's possible to hit this case).
        Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
        return false;
      }
      unsigned BaseEltSize = EltAsInt.getBitWidth();
      if (BigEndian)
        Res |= EltAsInt.zextOrTrunc(VecSize).rotr(i*EltSize+BaseEltSize);
      else
        Res |= EltAsInt.zextOrTrunc(VecSize).rotl(i*EltSize);
    }
    return true;
  }
  // Give up if the input isn't an int, float, or vector.  For example, we
  // reject "(v4i16)(intptr_t)&a".
  Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
  return false;
}

/// Perform the given integer operation, which is known to need at most BitWidth
/// bits, and check for overflow in the original type (if that type was not an
/// unsigned type).
template<typename Operation>
static bool CheckedIntArithmetic(EvalInfo &Info, const Expr *E,
                                 const APSInt &LHS, const APSInt &RHS,
                                 unsigned BitWidth, Operation Op,
                                 APSInt &Result) {
  if (LHS.isUnsigned()) {
    Result = Op(LHS, RHS);
    return true;
  }

  APSInt Value(Op(LHS.extend(BitWidth), RHS.extend(BitWidth)), false);
  Result = Value.trunc(LHS.getBitWidth());
  if (Result.extend(BitWidth) != Value) {
    if (Info.checkingForUndefinedBehavior())
      Info.Ctx.getDiagnostics().Report(E->getExprLoc(),
                                       diag::warn_integer_constant_overflow)
          << Result.toString(10) << E->getType();
    else
      return HandleOverflow(Info, E, Value, E->getType());
  }
  return true;
}

/// Perform the given binary integer operation.
static bool handleIntIntBinOp(EvalInfo &Info, const Expr *E, const APSInt &LHS,
                              BinaryOperatorKind Opcode, APSInt RHS,
                              APSInt &Result) {
  switch (Opcode) {
  default:
    Info.FFDiag(E);
    return false;
  case BO_Mul:
    return CheckedIntArithmetic(Info, E, LHS, RHS, LHS.getBitWidth() * 2,
                                std::multiplies<APSInt>(), Result);
  case BO_Add:
    return CheckedIntArithmetic(Info, E, LHS, RHS, LHS.getBitWidth() + 1,
                                std::plus<APSInt>(), Result);
  case BO_Sub:
    return CheckedIntArithmetic(Info, E, LHS, RHS, LHS.getBitWidth() + 1,
                                std::minus<APSInt>(), Result);
  case BO_And: Result = LHS & RHS; return true;
  case BO_Xor: Result = LHS ^ RHS; return true;
  case BO_Or:  Result = LHS | RHS; return true;
  case BO_Div:
  case BO_Rem:
    if (RHS == 0) {
      Info.FFDiag(E, diag::note_expr_divide_by_zero);
      return false;
    }
    Result = (Opcode == BO_Rem ? LHS % RHS : LHS / RHS);
    // Check for overflow case: INT_MIN / -1 or INT_MIN % -1. APSInt supports
    // this operation and gives the two's complement result.
    if (RHS.isNegative() && RHS.isAllOnesValue() &&
        LHS.isSigned() && LHS.isMinSignedValue())
      return HandleOverflow(Info, E, -LHS.extend(LHS.getBitWidth() + 1),
                            E->getType());
    return true;
  case BO_Shl: {
    if (Info.getLangOpts().OpenCL)
      // OpenCL 6.3j: shift values are effectively % word size of LHS.
      RHS &= APSInt(llvm::APInt(RHS.getBitWidth(),
                    static_cast<uint64_t>(LHS.getBitWidth() - 1)),
                    RHS.isUnsigned());
    else if (RHS.isSigned() && RHS.isNegative()) {
      // During constant-folding, a negative shift is an opposite shift. Such
      // a shift is not a constant expression.
      Info.CCEDiag(E, diag::note_constexpr_negative_shift) << RHS;
      RHS = -RHS;
      goto shift_right;
    }
  shift_left:
    // C++11 [expr.shift]p1: Shift width must be less than the bit width of
    // the shifted type.
    unsigned SA = (unsigned) RHS.getLimitedValue(LHS.getBitWidth()-1);
    if (SA != RHS) {
      Info.CCEDiag(E, diag::note_constexpr_large_shift)
        << RHS << E->getType() << LHS.getBitWidth();
    } else if (LHS.isSigned() && !Info.getLangOpts().CPlusPlus2a) {
      // C++11 [expr.shift]p2: A signed left shift must have a non-negative
      // operand, and must not overflow the corresponding unsigned type.
      // C++2a [expr.shift]p2: E1 << E2 is the unique value congruent to
      // E1 x 2^E2 module 2^N.
      if (LHS.isNegative())
        Info.CCEDiag(E, diag::note_constexpr_lshift_of_negative) << LHS;
      else if (LHS.countLeadingZeros() < SA)
        Info.CCEDiag(E, diag::note_constexpr_lshift_discards);
    }
    Result = LHS << SA;
    return true;
  }
  case BO_Shr: {
    if (Info.getLangOpts().OpenCL)
      // OpenCL 6.3j: shift values are effectively % word size of LHS.
      RHS &= APSInt(llvm::APInt(RHS.getBitWidth(),
                    static_cast<uint64_t>(LHS.getBitWidth() - 1)),
                    RHS.isUnsigned());
    else if (RHS.isSigned() && RHS.isNegative()) {
      // During constant-folding, a negative shift is an opposite shift. Such a
      // shift is not a constant expression.
      Info.CCEDiag(E, diag::note_constexpr_negative_shift) << RHS;
      RHS = -RHS;
      goto shift_left;
    }
  shift_right:
    // C++11 [expr.shift]p1: Shift width must be less than the bit width of the
    // shifted type.
    unsigned SA = (unsigned) RHS.getLimitedValue(LHS.getBitWidth()-1);
    if (SA != RHS)
      Info.CCEDiag(E, diag::note_constexpr_large_shift)
        << RHS << E->getType() << LHS.getBitWidth();
    Result = LHS >> SA;
    return true;
  }

  case BO_LT: Result = LHS < RHS; return true;
  case BO_GT: Result = LHS > RHS; return true;
  case BO_LE: Result = LHS <= RHS; return true;
  case BO_GE: Result = LHS >= RHS; return true;
  case BO_EQ: Result = LHS == RHS; return true;
  case BO_NE: Result = LHS != RHS; return true;
  case BO_Cmp:
    llvm_unreachable("BO_Cmp should be handled elsewhere");
  }
}

/// Perform the given binary floating-point operation, in-place, on LHS.
static bool handleFloatFloatBinOp(EvalInfo &Info, const Expr *E,
                                  APFloat &LHS, BinaryOperatorKind Opcode,
                                  const APFloat &RHS) {
  switch (Opcode) {
  default:
    Info.FFDiag(E);
    return false;
  case BO_Mul:
    LHS.multiply(RHS, APFloat::rmNearestTiesToEven);
    break;
  case BO_Add:
    LHS.add(RHS, APFloat::rmNearestTiesToEven);
    break;
  case BO_Sub:
    LHS.subtract(RHS, APFloat::rmNearestTiesToEven);
    break;
  case BO_Div:
    // [expr.mul]p4:
    //   If the second operand of / or % is zero the behavior is undefined.
    if (RHS.isZero())
      Info.CCEDiag(E, diag::note_expr_divide_by_zero);
    LHS.divide(RHS, APFloat::rmNearestTiesToEven);
    break;
  }

  // [expr.pre]p4:
  //   If during the evaluation of an expression, the result is not
  //   mathematically defined [...], the behavior is undefined.
  // FIXME: C++ rules require us to not conform to IEEE 754 here.
  if (LHS.isNaN()) {
    Info.CCEDiag(E, diag::note_constexpr_float_arithmetic) << LHS.isNaN();
    return Info.noteUndefinedBehavior();
  }
  return true;
}

/// Cast an lvalue referring to a base subobject to a derived class, by
/// truncating the lvalue's path to the given length.
static bool CastToDerivedClass(EvalInfo &Info, const Expr *E, LValue &Result,
                               const RecordDecl *TruncatedType,
                               unsigned TruncatedElements) {
  SubobjectDesignator &D = Result.Designator;

  // Check we actually point to a derived class object.
  if (TruncatedElements == D.Entries.size())
    return true;
  assert(TruncatedElements >= D.MostDerivedPathLength &&
         "not casting to a derived class");
  if (!Result.checkSubobject(Info, E, CSK_Derived))
    return false;

  // Truncate the path to the subobject, and remove any derived-to-base offsets.
  const RecordDecl *RD = TruncatedType;
  for (unsigned I = TruncatedElements, N = D.Entries.size(); I != N; ++I) {
    if (RD->isInvalidDecl()) return false;
    const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);
    const CXXRecordDecl *Base = getAsBaseClass(D.Entries[I]);
    if (isVirtualBaseClass(D.Entries[I]))
      Result.Offset -= Layout.getVBaseClassOffset(Base);
    else
      Result.Offset -= Layout.getBaseClassOffset(Base);
    RD = Base;
  }
  D.Entries.resize(TruncatedElements);
  return true;
}

static bool HandleLValueDirectBase(EvalInfo &Info, const Expr *E, LValue &Obj,
                                   const CXXRecordDecl *Derived,
                                   const CXXRecordDecl *Base,
                                   const ASTRecordLayout *RL = nullptr) {
  if (!RL) {
    if (Derived->isInvalidDecl()) return false;
    RL = &Info.Ctx.getASTRecordLayout(Derived);
  }

  Obj.getLValueOffset() += RL->getBaseClassOffset(Base);
  Obj.addDecl(Info, E, Base, /*Virtual*/ false);
  return true;
}

static bool HandleLValueBase(EvalInfo &Info, const Expr *E, LValue &Obj,
                             const CXXRecordDecl *DerivedDecl,
                             const CXXBaseSpecifier *Base) {
  const CXXRecordDecl *BaseDecl = Base->getType()->getAsCXXRecordDecl();

  if (!Base->isVirtual())
    return HandleLValueDirectBase(Info, E, Obj, DerivedDecl, BaseDecl);

  SubobjectDesignator &D = Obj.Designator;
  if (D.Invalid)
    return false;

  // Extract most-derived object and corresponding type.
  DerivedDecl = D.MostDerivedType->getAsCXXRecordDecl();
  if (!CastToDerivedClass(Info, E, Obj, DerivedDecl, D.MostDerivedPathLength))
    return false;

  // Find the virtual base class.
  if (DerivedDecl->isInvalidDecl()) return false;
  const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(DerivedDecl);
  Obj.getLValueOffset() += Layout.getVBaseClassOffset(BaseDecl);
  Obj.addDecl(Info, E, BaseDecl, /*Virtual*/ true);
  return true;
}

static bool HandleLValueBasePath(EvalInfo &Info, const CastExpr *E,
                                 QualType Type, LValue &Result) {
  for (CastExpr::path_const_iterator PathI = E->path_begin(),
                                     PathE = E->path_end();
       PathI != PathE; ++PathI) {
    if (!HandleLValueBase(Info, E, Result, Type->getAsCXXRecordDecl(),
                          *PathI))
      return false;
    Type = (*PathI)->getType();
  }
  return true;
}

/// Cast an lvalue referring to a derived class to a known base subobject.
static bool CastToBaseClass(EvalInfo &Info, const Expr *E, LValue &Result,
                            const CXXRecordDecl *DerivedRD,
                            const CXXRecordDecl *BaseRD) {
  CXXBasePaths Paths(/*FindAmbiguities=*/false,
                     /*RecordPaths=*/true, /*DetectVirtual=*/false);
  if (!DerivedRD->isDerivedFrom(BaseRD, Paths))
    llvm_unreachable("Class must be derived from the passed in base class!");

  for (CXXBasePathElement &Elem : Paths.front())
    if (!HandleLValueBase(Info, E, Result, Elem.Class, Elem.Base))
      return false;
  return true;
}

/// Update LVal to refer to the given field, which must be a member of the type
/// currently described by LVal.
static bool HandleLValueMember(EvalInfo &Info, const Expr *E, LValue &LVal,
                               const FieldDecl *FD,
                               const ASTRecordLayout *RL = nullptr) {
  if (!RL) {
    if (FD->getParent()->isInvalidDecl()) return false;
    RL = &Info.Ctx.getASTRecordLayout(FD->getParent());
  }

  unsigned I = FD->getFieldIndex();
  LVal.adjustOffset(Info.Ctx.toCharUnitsFromBits(RL->getFieldOffset(I)));
  LVal.addDecl(Info, E, FD);
  return true;
}

/// Update LVal to refer to the given indirect field.
static bool HandleLValueIndirectMember(EvalInfo &Info, const Expr *E,
                                       LValue &LVal,
                                       const IndirectFieldDecl *IFD) {
  for (const auto *C : IFD->chain())
    if (!HandleLValueMember(Info, E, LVal, cast<FieldDecl>(C)))
      return false;
  return true;
}

/// Get the size of the given type in char units.
static bool HandleSizeof(EvalInfo &Info, SourceLocation Loc,
                         QualType Type, CharUnits &Size) {
  // sizeof(void), __alignof__(void), sizeof(function) = 1 as a gcc
  // extension.
  if (Type->isVoidType() || Type->isFunctionType()) {
    Size = CharUnits::One();
    return true;
  }

  if (Type->isDependentType()) {
    Info.FFDiag(Loc);
    return false;
  }

  if (!Type->isConstantSizeType()) {
    // sizeof(vla) is not a constantexpr: C99 6.5.3.4p2.
    // FIXME: Better diagnostic.
    Info.FFDiag(Loc);
    return false;
  }

  Size = Info.Ctx.getTypeSizeInChars(Type);
  return true;
}

/// Update a pointer value to model pointer arithmetic.
/// \param Info - Information about the ongoing evaluation.
/// \param E - The expression being evaluated, for diagnostic purposes.
/// \param LVal - The pointer value to be updated.
/// \param EltTy - The pointee type represented by LVal.
/// \param Adjustment - The adjustment, in objects of type EltTy, to add.
static bool HandleLValueArrayAdjustment(EvalInfo &Info, const Expr *E,
                                        LValue &LVal, QualType EltTy,
                                        APSInt Adjustment) {
  CharUnits SizeOfPointee;
  if (!HandleSizeof(Info, E->getExprLoc(), EltTy, SizeOfPointee))
    return false;

  LVal.adjustOffsetAndIndex(Info, E, Adjustment, SizeOfPointee);
  return true;
}

static bool HandleLValueArrayAdjustment(EvalInfo &Info, const Expr *E,
                                        LValue &LVal, QualType EltTy,
                                        int64_t Adjustment) {
  return HandleLValueArrayAdjustment(Info, E, LVal, EltTy,
                                     APSInt::get(Adjustment));
}

/// Update an lvalue to refer to a component of a complex number.
/// \param Info - Information about the ongoing evaluation.
/// \param LVal - The lvalue to be updated.
/// \param EltTy - The complex number's component type.
/// \param Imag - False for the real component, true for the imaginary.
static bool HandleLValueComplexElement(EvalInfo &Info, const Expr *E,
                                       LValue &LVal, QualType EltTy,
                                       bool Imag) {
  if (Imag) {
    CharUnits SizeOfComponent;
    if (!HandleSizeof(Info, E->getExprLoc(), EltTy, SizeOfComponent))
      return false;
    LVal.Offset += SizeOfComponent;
  }
  LVal.addComplex(Info, E, EltTy, Imag);
  return true;
}

/// Try to evaluate the initializer for a variable declaration.
///
/// \param Info   Information about the ongoing evaluation.
/// \param E      An expression to be used when printing diagnostics.
/// \param VD     The variable whose initializer should be obtained.
/// \param Frame  The frame in which the variable was created. Must be null
///               if this variable is not local to the evaluation.
/// \param Result Filled in with a pointer to the value of the variable.
static bool evaluateVarDeclInit(EvalInfo &Info, const Expr *E,
                                const VarDecl *VD, CallStackFrame *Frame,
                                APValue *&Result, const LValue *LVal) {

  // If this is a parameter to an active constexpr function call, perform
  // argument substitution.
  if (const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(VD)) {
    // Assume arguments of a potential constant expression are unknown
    // constant expressions.
    if (Info.checkingPotentialConstantExpression())
      return false;
    if (!Frame || !Frame->Arguments) {
      Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
      return false;
    }
    Result = &Frame->Arguments[PVD->getFunctionScopeIndex()];
    return true;
  }

  // If this is a local variable, dig out its value.
  if (Frame) {
    Result = LVal ? Frame->getTemporary(VD, LVal->getLValueVersion())
                  : Frame->getCurrentTemporary(VD);
    if (!Result) {
      // Assume variables referenced within a lambda's call operator that were
      // not declared within the call operator are captures and during checking
      // of a potential constant expression, assume they are unknown constant
      // expressions.
      assert(isLambdaCallOperator(Frame->Callee) &&
             (VD->getDeclContext() != Frame->Callee || VD->isInitCapture()) &&
             "missing value for local variable");
      if (Info.checkingPotentialConstantExpression())
        return false;
      // FIXME: implement capture evaluation during constant expr evaluation.
      Info.FFDiag(E->getBeginLoc(),
                  diag::note_unimplemented_constexpr_lambda_feature_ast)
          << "captures not currently allowed";
      return false;
    }
    return true;
  }

  // Dig out the initializer, and use the declaration which it's attached to.
  const Expr *Init = VD->getAnyInitializer(VD);
  if (!Init || Init->isValueDependent()) {
    // If we're checking a potential constant expression, the variable could be
    // initialized later.
    if (!Info.checkingPotentialConstantExpression())
      Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  // If we're currently evaluating the initializer of this declaration, use that
  // in-flight value.
  if (Info.EvaluatingDecl.dyn_cast<const ValueDecl*>() == VD) {
    Result = Info.EvaluatingDeclValue;
    return true;
  }

  // Never evaluate the initializer of a weak variable. We can't be sure that
  // this is the definition which will be used.
  if (VD->isWeak()) {
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  // Check that we can fold the initializer. In C++, we will have already done
  // this in the cases where it matters for conformance.
  SmallVector<PartialDiagnosticAt, 8> Notes;
  if (!VD->evaluateValue(Notes)) {
    Info.FFDiag(E, diag::note_constexpr_var_init_non_constant,
              Notes.size() + 1) << VD;
    Info.Note(VD->getLocation(), diag::note_declared_at);
    Info.addNotes(Notes);
    return false;
  } else if (!VD->checkInitIsICE()) {
    Info.CCEDiag(E, diag::note_constexpr_var_init_non_constant,
                 Notes.size() + 1) << VD;
    Info.Note(VD->getLocation(), diag::note_declared_at);
    Info.addNotes(Notes);
  }

  Result = VD->getEvaluatedValue();
  return true;
}

static bool IsConstNonVolatile(QualType T) {
  Qualifiers Quals = T.getQualifiers();
  return Quals.hasConst() && !Quals.hasVolatile();
}

/// Get the base index of the given base class within an APValue representing
/// the given derived class.
static unsigned getBaseIndex(const CXXRecordDecl *Derived,
                             const CXXRecordDecl *Base) {
  Base = Base->getCanonicalDecl();
  unsigned Index = 0;
  for (CXXRecordDecl::base_class_const_iterator I = Derived->bases_begin(),
         E = Derived->bases_end(); I != E; ++I, ++Index) {
    if (I->getType()->getAsCXXRecordDecl()->getCanonicalDecl() == Base)
      return Index;
  }

  llvm_unreachable("base class missing from derived class's bases list");
}

/// Extract the value of a character from a string literal.
static APSInt extractStringLiteralCharacter(EvalInfo &Info, const Expr *Lit,
                                            uint64_t Index) {
  assert(!isa<SourceLocExpr>(Lit) &&
         "SourceLocExpr should have already been converted to a StringLiteral");

  // FIXME: Support MakeStringConstant
  if (const auto *ObjCEnc = dyn_cast<ObjCEncodeExpr>(Lit)) {
    std::string Str;
    Info.Ctx.getObjCEncodingForType(ObjCEnc->getEncodedType(), Str);
    assert(Index <= Str.size() && "Index too large");
    return APSInt::getUnsigned(Str.c_str()[Index]);
  }

  if (auto PE = dyn_cast<PredefinedExpr>(Lit))
    Lit = PE->getFunctionName();
  const StringLiteral *S = cast<StringLiteral>(Lit);
  const ConstantArrayType *CAT =
      Info.Ctx.getAsConstantArrayType(S->getType());
  assert(CAT && "string literal isn't an array");
  QualType CharType = CAT->getElementType();
  assert(CharType->isIntegerType() && "unexpected character type");

  APSInt Value(S->getCharByteWidth() * Info.Ctx.getCharWidth(),
               CharType->isUnsignedIntegerType());
  if (Index < S->getLength())
    Value = S->getCodeUnit(Index);
  return Value;
}

// Expand a string literal into an array of characters.
//
// FIXME: This is inefficient; we should probably introduce something similar
// to the LLVM ConstantDataArray to make this cheaper.
static void expandStringLiteral(EvalInfo &Info, const StringLiteral *S,
                                APValue &Result,
                                QualType AllocType = QualType()) {
  const ConstantArrayType *CAT = Info.Ctx.getAsConstantArrayType(
      AllocType.isNull() ? S->getType() : AllocType);
  assert(CAT && "string literal isn't an array");
  QualType CharType = CAT->getElementType();
  assert(CharType->isIntegerType() && "unexpected character type");

  unsigned Elts = CAT->getSize().getZExtValue();
  Result = APValue(APValue::UninitArray(),
                   std::min(S->getLength(), Elts), Elts);
  APSInt Value(S->getCharByteWidth() * Info.Ctx.getCharWidth(),
               CharType->isUnsignedIntegerType());
  if (Result.hasArrayFiller())
    Result.getArrayFiller() = APValue(Value);
  for (unsigned I = 0, N = Result.getArrayInitializedElts(); I != N; ++I) {
    Value = S->getCodeUnit(I);
    Result.getArrayInitializedElt(I) = APValue(Value);
  }
}

// Expand an array so that it has more than Index filled elements.
static void expandArray(APValue &Array, unsigned Index) {
  unsigned Size = Array.getArraySize();
  assert(Index < Size);

  // Always at least double the number of elements for which we store a value.
  unsigned OldElts = Array.getArrayInitializedElts();
  unsigned NewElts = std::max(Index+1, OldElts * 2);
  NewElts = std::min(Size, std::max(NewElts, 8u));

  // Copy the data across.
  APValue NewValue(APValue::UninitArray(), NewElts, Size);
  for (unsigned I = 0; I != OldElts; ++I)
    NewValue.getArrayInitializedElt(I).swap(Array.getArrayInitializedElt(I));
  for (unsigned I = OldElts; I != NewElts; ++I)
    NewValue.getArrayInitializedElt(I) = Array.getArrayFiller();
  if (NewValue.hasArrayFiller())
    NewValue.getArrayFiller() = Array.getArrayFiller();
  Array.swap(NewValue);
}

/// Determine whether a type would actually be read by an lvalue-to-rvalue
/// conversion. If it's of class type, we may assume that the copy operation
/// is trivial. Note that this is never true for a union type with fields
/// (because the copy always "reads" the active member) and always true for
/// a non-class type.
static bool isReadByLvalueToRvalueConversion(QualType T) {
  CXXRecordDecl *RD = T->getBaseElementTypeUnsafe()->getAsCXXRecordDecl();
  if (!RD || (RD->isUnion() && !RD->field_empty()))
    return true;
  if (RD->isEmpty())
    return false;

  for (auto *Field : RD->fields())
    if (isReadByLvalueToRvalueConversion(Field->getType()))
      return true;

  for (auto &BaseSpec : RD->bases())
    if (isReadByLvalueToRvalueConversion(BaseSpec.getType()))
      return true;

  return false;
}

/// Diagnose an attempt to read from any unreadable field within the specified
/// type, which might be a class type.
static bool diagnoseMutableFields(EvalInfo &Info, const Expr *E, AccessKinds AK,
                                  QualType T) {
  CXXRecordDecl *RD = T->getBaseElementTypeUnsafe()->getAsCXXRecordDecl();
  if (!RD)
    return false;

  if (!RD->hasMutableFields())
    return false;

  for (auto *Field : RD->fields()) {
    // If we're actually going to read this field in some way, then it can't
    // be mutable. If we're in a union, then assigning to a mutable field
    // (even an empty one) can change the active member, so that's not OK.
    // FIXME: Add core issue number for the union case.
    if (Field->isMutable() &&
        (RD->isUnion() || isReadByLvalueToRvalueConversion(Field->getType()))) {
      Info.FFDiag(E, diag::note_constexpr_access_mutable, 1) << AK << Field;
      Info.Note(Field->getLocation(), diag::note_declared_at);
      return true;
    }

    if (diagnoseMutableFields(Info, E, AK, Field->getType()))
      return true;
  }

  for (auto &BaseSpec : RD->bases())
    if (diagnoseMutableFields(Info, E, AK, BaseSpec.getType()))
      return true;

  // All mutable fields were empty, and thus not actually read.
  return false;
}

static bool lifetimeStartedInEvaluation(EvalInfo &Info,
                                        APValue::LValueBase Base,
                                        bool MutableSubobject = false) {
  // A temporary we created.
  if (Base.getCallIndex())
    return true;

  auto *Evaluating = Info.EvaluatingDecl.dyn_cast<const ValueDecl*>();
  if (!Evaluating)
    return false;

  auto *BaseD = Base.dyn_cast<const ValueDecl*>();

  switch (Info.IsEvaluatingDecl) {
  case EvalInfo::EvaluatingDeclKind::None:
    return false;

  case EvalInfo::EvaluatingDeclKind::Ctor:
    // The variable whose initializer we're evaluating.
    if (BaseD)
      return declaresSameEntity(Evaluating, BaseD);

    // A temporary lifetime-extended by the variable whose initializer we're
    // evaluating.
    if (auto *BaseE = Base.dyn_cast<const Expr *>())
      if (auto *BaseMTE = dyn_cast<MaterializeTemporaryExpr>(BaseE))
        return declaresSameEntity(BaseMTE->getExtendingDecl(), Evaluating);
    return false;

  case EvalInfo::EvaluatingDeclKind::Dtor:
    // C++2a [expr.const]p6:
    //   [during constant destruction] the lifetime of a and its non-mutable
    //   subobjects (but not its mutable subobjects) [are] considered to start
    //   within e.
    //
    // FIXME: We can meaningfully extend this to cover non-const objects, but
    // we will need special handling: we should be able to access only
    // subobjects of such objects that are themselves declared const.
    if (!BaseD ||
        !(BaseD->getType().isConstQualified() ||
          BaseD->getType()->isReferenceType()) ||
        MutableSubobject)
      return false;
    return declaresSameEntity(Evaluating, BaseD);
  }

  llvm_unreachable("unknown evaluating decl kind");
}

namespace {
/// A handle to a complete object (an object that is not a subobject of
/// another object).
struct CompleteObject {
  /// The identity of the object.
  APValue::LValueBase Base;
  /// The value of the complete object.
  APValue *Value;
  /// The type of the complete object.
  QualType Type;

  CompleteObject() : Value(nullptr) {}
  CompleteObject(APValue::LValueBase Base, APValue *Value, QualType Type)
      : Base(Base), Value(Value), Type(Type) {}

  bool mayAccessMutableMembers(EvalInfo &Info, AccessKinds AK) const {
    // In C++14 onwards, it is permitted to read a mutable member whose
    // lifetime began within the evaluation.
    // FIXME: Should we also allow this in C++11?
    if (!Info.getLangOpts().CPlusPlus14)
      return false;
    return lifetimeStartedInEvaluation(Info, Base, /*MutableSubobject*/true);
  }

  explicit operator bool() const { return !Type.isNull(); }
};
} // end anonymous namespace

static QualType getSubobjectType(QualType ObjType, QualType SubobjType,
                                 bool IsMutable = false) {
  // C++ [basic.type.qualifier]p1:
  // - A const object is an object of type const T or a non-mutable subobject
  //   of a const object.
  if (ObjType.isConstQualified() && !IsMutable)
    SubobjType.addConst();
  // - A volatile object is an object of type const T or a subobject of a
  //   volatile object.
  if (ObjType.isVolatileQualified())
    SubobjType.addVolatile();
  return SubobjType;
}

/// Find the designated sub-object of an rvalue.
template<typename SubobjectHandler>
typename SubobjectHandler::result_type
findSubobject(EvalInfo &Info, const Expr *E, const CompleteObject &Obj,
              const SubobjectDesignator &Sub, SubobjectHandler &handler) {
  if (Sub.Invalid)
    // A diagnostic will have already been produced.
    return handler.failed();
  if (Sub.isOnePastTheEnd() || Sub.isMostDerivedAnUnsizedArray()) {
    if (Info.getLangOpts().CPlusPlus11)
      Info.FFDiag(E, Sub.isOnePastTheEnd()
                         ? diag::note_constexpr_access_past_end
                         : diag::note_constexpr_access_unsized_array)
          << handler.AccessKind;
    else
      Info.FFDiag(E);
    return handler.failed();
  }

  APValue *O = Obj.Value;
  QualType ObjType = Obj.Type;
  const FieldDecl *LastField = nullptr;
  const FieldDecl *VolatileField = nullptr;

  // Walk the designator's path to find the subobject.
  for (unsigned I = 0, N = Sub.Entries.size(); /**/; ++I) {
    // Reading an indeterminate value is undefined, but assigning over one is OK.
    if ((O->isAbsent() && !(handler.AccessKind == AK_Construct && I == N)) ||
        (O->isIndeterminate() && handler.AccessKind != AK_Construct &&
         handler.AccessKind != AK_Assign &&
         handler.AccessKind != AK_ReadObjectRepresentation)) {
      if (!Info.checkingPotentialConstantExpression())
        Info.FFDiag(E, diag::note_constexpr_access_uninit)
            << handler.AccessKind << O->isIndeterminate();
      return handler.failed();
    }

    // C++ [class.ctor]p5, C++ [class.dtor]p5:
    //    const and volatile semantics are not applied on an object under
    //    {con,de}struction.
    if ((ObjType.isConstQualified() || ObjType.isVolatileQualified()) &&
        ObjType->isRecordType() &&
        Info.isEvaluatingCtorDtor(
            Obj.Base, llvm::makeArrayRef(Sub.Entries.begin(),
                                         Sub.Entries.begin() + I)) !=
                          ConstructionPhase::None) {
      ObjType = Info.Ctx.getCanonicalType(ObjType);
      ObjType.removeLocalConst();
      ObjType.removeLocalVolatile();
    }

    // If this is our last pass, check that the final object type is OK.
    if (I == N || (I == N - 1 && ObjType->isAnyComplexType())) {
      // Accesses to volatile objects are prohibited.
      if (ObjType.isVolatileQualified() && isFormalAccess(handler.AccessKind)) {
        if (Info.getLangOpts().CPlusPlus) {
          int DiagKind;
          SourceLocation Loc;
          const NamedDecl *Decl = nullptr;
          if (VolatileField) {
            DiagKind = 2;
            Loc = VolatileField->getLocation();
            Decl = VolatileField;
          } else if (auto *VD = Obj.Base.dyn_cast<const ValueDecl*>()) {
            DiagKind = 1;
            Loc = VD->getLocation();
            Decl = VD;
          } else {
            DiagKind = 0;
            if (auto *E = Obj.Base.dyn_cast<const Expr *>())
              Loc = E->getExprLoc();
          }
          Info.FFDiag(E, diag::note_constexpr_access_volatile_obj, 1)
              << handler.AccessKind << DiagKind << Decl;
          Info.Note(Loc, diag::note_constexpr_volatile_here) << DiagKind;
        } else {
          Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
        }
        return handler.failed();
      }

      // If we are reading an object of class type, there may still be more
      // things we need to check: if there are any mutable subobjects, we
      // cannot perform this read. (This only happens when performing a trivial
      // copy or assignment.)
      if (ObjType->isRecordType() &&
          !Obj.mayAccessMutableMembers(Info, handler.AccessKind) &&
          diagnoseMutableFields(Info, E, handler.AccessKind, ObjType))
        return handler.failed();
    }

    if (I == N) {
      if (!handler.found(*O, ObjType))
        return false;

      // If we modified a bit-field, truncate it to the right width.
      if (isModification(handler.AccessKind) &&
          LastField && LastField->isBitField() &&
          !truncateBitfieldValue(Info, E, *O, LastField))
        return false;

      return true;
    }

    LastField = nullptr;
    if (ObjType->isArrayType()) {
      // Next subobject is an array element.
      const ConstantArrayType *CAT = Info.Ctx.getAsConstantArrayType(ObjType);
      assert(CAT && "vla in literal type?");
      uint64_t Index = Sub.Entries[I].getAsArrayIndex();
      if (CAT->getSize().ule(Index)) {
        // Note, it should not be possible to form a pointer with a valid
        // designator which points more than one past the end of the array.
        if (Info.getLangOpts().CPlusPlus11)
          Info.FFDiag(E, diag::note_constexpr_access_past_end)
            << handler.AccessKind;
        else
          Info.FFDiag(E);
        return handler.failed();
      }

      ObjType = CAT->getElementType();

      if (O->getArrayInitializedElts() > Index)
        O = &O->getArrayInitializedElt(Index);
      else if (!isRead(handler.AccessKind)) {
        expandArray(*O, Index);
        O = &O->getArrayInitializedElt(Index);
      } else
        O = &O->getArrayFiller();
    } else if (ObjType->isAnyComplexType()) {
      // Next subobject is a complex number.
      uint64_t Index = Sub.Entries[I].getAsArrayIndex();
      if (Index > 1) {
        if (Info.getLangOpts().CPlusPlus11)
          Info.FFDiag(E, diag::note_constexpr_access_past_end)
            << handler.AccessKind;
        else
          Info.FFDiag(E);
        return handler.failed();
      }

      ObjType = getSubobjectType(
          ObjType, ObjType->castAs<ComplexType>()->getElementType());

      assert(I == N - 1 && "extracting subobject of scalar?");
      if (O->isComplexInt()) {
        return handler.found(Index ? O->getComplexIntImag()
                                   : O->getComplexIntReal(), ObjType);
      } else {
        assert(O->isComplexFloat());
        return handler.found(Index ? O->getComplexFloatImag()
                                   : O->getComplexFloatReal(), ObjType);
      }
    } else if (const FieldDecl *Field = getAsField(Sub.Entries[I])) {
      if (Field->isMutable() &&
          !Obj.mayAccessMutableMembers(Info, handler.AccessKind)) {
        Info.FFDiag(E, diag::note_constexpr_access_mutable, 1)
          << handler.AccessKind << Field;
        Info.Note(Field->getLocation(), diag::note_declared_at);
        return handler.failed();
      }

      // Next subobject is a class, struct or union field.
      RecordDecl *RD = ObjType->castAs<RecordType>()->getDecl();
      if (RD->isUnion()) {
        const FieldDecl *UnionField = O->getUnionField();
        if (!UnionField ||
            UnionField->getCanonicalDecl() != Field->getCanonicalDecl()) {
          if (I == N - 1 && handler.AccessKind == AK_Construct) {
            // Placement new onto an inactive union member makes it active.
            O->setUnion(Field, APValue());
          } else {
            // FIXME: If O->getUnionValue() is absent, report that there's no
            // active union member rather than reporting the prior active union
            // member. We'll need to fix nullptr_t to not use APValue() as its
            // representation first.
            Info.FFDiag(E, diag::note_constexpr_access_inactive_union_member)
                << handler.AccessKind << Field << !UnionField << UnionField;
            return handler.failed();
          }
        }
        O = &O->getUnionValue();
      } else
        O = &O->getStructField(Field->getFieldIndex());

      ObjType = getSubobjectType(ObjType, Field->getType(), Field->isMutable());
      LastField = Field;
      if (Field->getType().isVolatileQualified())
        VolatileField = Field;
    } else {
      // Next subobject is a base class.
      const CXXRecordDecl *Derived = ObjType->getAsCXXRecordDecl();
      const CXXRecordDecl *Base = getAsBaseClass(Sub.Entries[I]);
      O = &O->getStructBase(getBaseIndex(Derived, Base));

      ObjType = getSubobjectType(ObjType, Info.Ctx.getRecordType(Base));
    }
  }
}

namespace {
struct ExtractSubobjectHandler {
  EvalInfo &Info;
  const Expr *E;
  APValue &Result;
  const AccessKinds AccessKind;

  typedef bool result_type;
  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    Result = Subobj;
    if (AccessKind == AK_ReadObjectRepresentation)
      return true;
    return CheckFullyInitialized(Info, E->getExprLoc(), SubobjType, Result);
  }
  bool found(APSInt &Value, QualType SubobjType) {
    Result = APValue(Value);
    return true;
  }
  bool found(APFloat &Value, QualType SubobjType) {
    Result = APValue(Value);
    return true;
  }
};
} // end anonymous namespace

/// Extract the designated sub-object of an rvalue.
static bool extractSubobject(EvalInfo &Info, const Expr *E,
                             const CompleteObject &Obj,
                             const SubobjectDesignator &Sub, APValue &Result,
                             AccessKinds AK = AK_Read) {
  assert(AK == AK_Read || AK == AK_ReadObjectRepresentation);
  ExtractSubobjectHandler Handler = {Info, E, Result, AK};
  return findSubobject(Info, E, Obj, Sub, Handler);
}

namespace {
struct ModifySubobjectHandler {
  EvalInfo &Info;
  APValue &NewVal;
  const Expr *E;

  typedef bool result_type;
  static const AccessKinds AccessKind = AK_Assign;

  bool checkConst(QualType QT) {
    // Assigning to a const object has undefined behavior.
    if (QT.isConstQualified()) {
      Info.FFDiag(E, diag::note_constexpr_modify_const_type) << QT;
      return false;
    }
    return true;
  }

  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;
    // We've been given ownership of NewVal, so just swap it in.
    Subobj.swap(NewVal);
    return true;
  }
  bool found(APSInt &Value, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;
    if (!NewVal.isInt()) {
      // Maybe trying to write a cast pointer value into a complex?
      Info.FFDiag(E);
      return false;
    }
    Value = NewVal.getInt();
    return true;
  }
  bool found(APFloat &Value, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;
    Value = NewVal.getFloat();
    return true;
  }
};
} // end anonymous namespace

const AccessKinds ModifySubobjectHandler::AccessKind;

/// Update the designated sub-object of an rvalue to the given value.
static bool modifySubobject(EvalInfo &Info, const Expr *E,
                            const CompleteObject &Obj,
                            const SubobjectDesignator &Sub,
                            APValue &NewVal) {
  ModifySubobjectHandler Handler = { Info, NewVal, E };
  return findSubobject(Info, E, Obj, Sub, Handler);
}

/// Find the position where two subobject designators diverge, or equivalently
/// the length of the common initial subsequence.
static unsigned FindDesignatorMismatch(QualType ObjType,
                                       const SubobjectDesignator &A,
                                       const SubobjectDesignator &B,
                                       bool &WasArrayIndex) {
  unsigned I = 0, N = std::min(A.Entries.size(), B.Entries.size());
  for (/**/; I != N; ++I) {
    if (!ObjType.isNull() &&
        (ObjType->isArrayType() || ObjType->isAnyComplexType())) {
      // Next subobject is an array element.
      if (A.Entries[I].getAsArrayIndex() != B.Entries[I].getAsArrayIndex()) {
        WasArrayIndex = true;
        return I;
      }
      if (ObjType->isAnyComplexType())
        ObjType = ObjType->castAs<ComplexType>()->getElementType();
      else
        ObjType = ObjType->castAsArrayTypeUnsafe()->getElementType();
    } else {
      if (A.Entries[I].getAsBaseOrMember() !=
          B.Entries[I].getAsBaseOrMember()) {
        WasArrayIndex = false;
        return I;
      }
      if (const FieldDecl *FD = getAsField(A.Entries[I]))
        // Next subobject is a field.
        ObjType = FD->getType();
      else
        // Next subobject is a base class.
        ObjType = QualType();
    }
  }
  WasArrayIndex = false;
  return I;
}

/// Determine whether the given subobject designators refer to elements of the
/// same array object.
static bool AreElementsOfSameArray(QualType ObjType,
                                   const SubobjectDesignator &A,
                                   const SubobjectDesignator &B) {
  if (A.Entries.size() != B.Entries.size())
    return false;

  bool IsArray = A.MostDerivedIsArrayElement;
  if (IsArray && A.MostDerivedPathLength != A.Entries.size())
    // A is a subobject of the array element.
    return false;

  // If A (and B) designates an array element, the last entry will be the array
  // index. That doesn't have to match. Otherwise, we're in the 'implicit array
  // of length 1' case, and the entire path must match.
  bool WasArrayIndex;
  unsigned CommonLength = FindDesignatorMismatch(ObjType, A, B, WasArrayIndex);
  return CommonLength >= A.Entries.size() - IsArray;
}

/// Find the complete object to which an LValue refers.
static CompleteObject findCompleteObject(EvalInfo &Info, const Expr *E,
                                         AccessKinds AK, const LValue &LVal,
                                         QualType LValType) {
  if (LVal.InvalidBase) {
    Info.FFDiag(E);
    return CompleteObject();
  }

  if (!LVal.Base) {
    Info.FFDiag(E, diag::note_constexpr_access_null) << AK;
    return CompleteObject();
  }

  CallStackFrame *Frame = nullptr;
  unsigned Depth = 0;
  if (LVal.getLValueCallIndex()) {
    std::tie(Frame, Depth) =
        Info.getCallFrameAndDepth(LVal.getLValueCallIndex());
    if (!Frame) {
      Info.FFDiag(E, diag::note_constexpr_lifetime_ended, 1)
        << AK << LVal.Base.is<const ValueDecl*>();
      NoteLValueLocation(Info, LVal.Base);
      return CompleteObject();
    }
  }

  bool IsAccess = isAnyAccess(AK);

  // C++11 DR1311: An lvalue-to-rvalue conversion on a volatile-qualified type
  // is not a constant expression (even if the object is non-volatile). We also
  // apply this rule to C++98, in order to conform to the expected 'volatile'
  // semantics.
  if (isFormalAccess(AK) && LValType.isVolatileQualified()) {
    if (Info.getLangOpts().CPlusPlus)
      Info.FFDiag(E, diag::note_constexpr_access_volatile_type)
        << AK << LValType;
    else
      Info.FFDiag(E);
    return CompleteObject();
  }

  // Compute value storage location and type of base object.
  APValue *BaseVal = nullptr;
  QualType BaseType = getType(LVal.Base);

  if (const ValueDecl *D = LVal.Base.dyn_cast<const ValueDecl*>()) {
    // In C++98, const, non-volatile integers initialized with ICEs are ICEs.
    // In C++11, constexpr, non-volatile variables initialized with constant
    // expressions are constant expressions too. Inside constexpr functions,
    // parameters are constant expressions even if they're non-const.
    // In C++1y, objects local to a constant expression (those with a Frame) are
    // both readable and writable inside constant expressions.
    // In C, such things can also be folded, although they are not ICEs.
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (VD) {
      if (const VarDecl *VDef = VD->getDefinition(Info.Ctx))
        VD = VDef;
    }
    if (!VD || VD->isInvalidDecl()) {
      Info.FFDiag(E);
      return CompleteObject();
    }

    // Unless we're looking at a local variable or argument in a constexpr call,
    // the variable we're reading must be const.
    if (!Frame) {
      if (Info.getLangOpts().CPlusPlus14 &&
          lifetimeStartedInEvaluation(Info, LVal.Base)) {
        // OK, we can read and modify an object if we're in the process of
        // evaluating its initializer, because its lifetime began in this
        // evaluation.
      } else if (isModification(AK)) {
        // All the remaining cases do not permit modification of the object.
        Info.FFDiag(E, diag::note_constexpr_modify_global);
        return CompleteObject();
      } else if (VD->isConstexpr()) {
        // OK, we can read this variable.
      } else if (BaseType->isIntegralOrEnumerationType()) {
        // In OpenCL if a variable is in constant address space it is a const
        // value.
        if (!(BaseType.isConstQualified() ||
              (Info.getLangOpts().OpenCL &&
               BaseType.getAddressSpace() == LangAS::opencl_constant))) {
          if (!IsAccess)
            return CompleteObject(LVal.getLValueBase(), nullptr, BaseType);
          if (Info.getLangOpts().CPlusPlus) {
            Info.FFDiag(E, diag::note_constexpr_ltor_non_const_int, 1) << VD;
            Info.Note(VD->getLocation(), diag::note_declared_at);
          } else {
            Info.FFDiag(E);
          }
          return CompleteObject();
        }
      } else if (!IsAccess) {
        return CompleteObject(LVal.getLValueBase(), nullptr, BaseType);
      } else if (BaseType->isFloatingType() && BaseType.isConstQualified()) {
        // We support folding of const floating-point types, in order to make
        // static const data members of such types (supported as an extension)
        // more useful.
        if (Info.getLangOpts().CPlusPlus11) {
          Info.CCEDiag(E, diag::note_constexpr_ltor_non_constexpr, 1) << VD;
          Info.Note(VD->getLocation(), diag::note_declared_at);
        } else {
          Info.CCEDiag(E);
        }
      } else if (BaseType.isConstQualified() && VD->hasDefinition(Info.Ctx)) {
        Info.CCEDiag(E, diag::note_constexpr_ltor_non_constexpr) << VD;
        // Keep evaluating to see what we can do.
      } else {
        // FIXME: Allow folding of values of any literal type in all languages.
        if (Info.checkingPotentialConstantExpression() &&
            VD->getType().isConstQualified() && !VD->hasDefinition(Info.Ctx)) {
          // The definition of this variable could be constexpr. We can't
          // access it right now, but may be able to in future.
        } else if (Info.getLangOpts().CPlusPlus11) {
          Info.FFDiag(E, diag::note_constexpr_ltor_non_constexpr, 1) << VD;
          Info.Note(VD->getLocation(), diag::note_declared_at);
        } else {
          Info.FFDiag(E);
        }
        return CompleteObject();
      }
    }

    if (!evaluateVarDeclInit(Info, E, VD, Frame, BaseVal, &LVal))
      return CompleteObject();
  } else if (DynamicAllocLValue DA = LVal.Base.dyn_cast<DynamicAllocLValue>()) {
    Optional<DynAlloc*> Alloc = Info.lookupDynamicAlloc(DA);
    if (!Alloc) {
      Info.FFDiag(E, diag::note_constexpr_access_deleted_object) << AK;
      return CompleteObject();
    }
    return CompleteObject(LVal.Base, &(*Alloc)->Value,
                          LVal.Base.getDynamicAllocType());
  } else {
    const Expr *Base = LVal.Base.dyn_cast<const Expr*>();

    if (!Frame) {
      if (const MaterializeTemporaryExpr *MTE =
              dyn_cast_or_null<MaterializeTemporaryExpr>(Base)) {
        assert(MTE->getStorageDuration() == SD_Static &&
               "should have a frame for a non-global materialized temporary");

        // Per C++1y [expr.const]p2:
        //  an lvalue-to-rvalue conversion [is not allowed unless it applies to]
        //   - a [...] glvalue of integral or enumeration type that refers to
        //     a non-volatile const object [...]
        //   [...]
        //   - a [...] glvalue of literal type that refers to a non-volatile
        //     object whose lifetime began within the evaluation of e.
        //
        // C++11 misses the 'began within the evaluation of e' check and
        // instead allows all temporaries, including things like:
        //   int &&r = 1;
        //   int x = ++r;
        //   constexpr int k = r;
        // Therefore we use the C++14 rules in C++11 too.
        //
        // Note that temporaries whose lifetimes began while evaluating a
        // variable's constructor are not usable while evaluating the
        // corresponding destructor, not even if they're of const-qualified
        // types.
        if (!(BaseType.isConstQualified() &&
              BaseType->isIntegralOrEnumerationType()) &&
            !lifetimeStartedInEvaluation(Info, LVal.Base)) {
          if (!IsAccess)
            return CompleteObject(LVal.getLValueBase(), nullptr, BaseType);
          Info.FFDiag(E, diag::note_constexpr_access_static_temporary, 1) << AK;
          Info.Note(MTE->getExprLoc(), diag::note_constexpr_temporary_here);
          return CompleteObject();
        }

        BaseVal = MTE->getOrCreateValue(false);
        assert(BaseVal && "got reference to unevaluated temporary");
      } else {
        if (!IsAccess)
          return CompleteObject(LVal.getLValueBase(), nullptr, BaseType);
        APValue Val;
        LVal.moveInto(Val);
        Info.FFDiag(E, diag::note_constexpr_access_unreadable_object)
            << AK
            << Val.getAsString(Info.Ctx,
                               Info.Ctx.getLValueReferenceType(LValType));
        NoteLValueLocation(Info, LVal.Base);
        return CompleteObject();
      }
    } else {
      BaseVal = Frame->getTemporary(Base, LVal.Base.getVersion());
      assert(BaseVal && "missing value for temporary");
    }
  }

  // In C++14, we can't safely access any mutable state when we might be
  // evaluating after an unmodeled side effect.
  //
  // FIXME: Not all local state is mutable. Allow local constant subobjects
  // to be read here (but take care with 'mutable' fields).
  if ((Frame && Info.getLangOpts().CPlusPlus14 &&
       Info.EvalStatus.HasSideEffects) ||
      (isModification(AK) && Depth < Info.SpeculativeEvaluationDepth))
    return CompleteObject();

  return CompleteObject(LVal.getLValueBase(), BaseVal, BaseType);
}

/// Perform an lvalue-to-rvalue conversion on the given glvalue. This
/// can also be used for 'lvalue-to-lvalue' conversions for looking up the
/// glvalue referred to by an entity of reference type.
///
/// \param Info - Information about the ongoing evaluation.
/// \param Conv - The expression for which we are performing the conversion.
///               Used for diagnostics.
/// \param Type - The type of the glvalue (before stripping cv-qualifiers in the
///               case of a non-class type).
/// \param LVal - The glvalue on which we are attempting to perform this action.
/// \param RVal - The produced value will be placed here.
/// \param WantObjectRepresentation - If true, we're looking for the object
///               representation rather than the value, and in particular,
///               there is no requirement that the result be fully initialized.
static bool
handleLValueToRValueConversion(EvalInfo &Info, const Expr *Conv, QualType Type,
                               const LValue &LVal, APValue &RVal,
                               bool WantObjectRepresentation = false) {
  if (LVal.Designator.Invalid)
    return false;

  // Check for special cases where there is no existing APValue to look at.
  const Expr *Base = LVal.Base.dyn_cast<const Expr*>();

  AccessKinds AK =
      WantObjectRepresentation ? AK_ReadObjectRepresentation : AK_Read;

  if (Base && !LVal.getLValueCallIndex() && !Type.isVolatileQualified()) {
    if (const CompoundLiteralExpr *CLE = dyn_cast<CompoundLiteralExpr>(Base)) {
      // In C99, a CompoundLiteralExpr is an lvalue, and we defer evaluating the
      // initializer until now for such expressions. Such an expression can't be
      // an ICE in C, so this only matters for fold.
      if (Type.isVolatileQualified()) {
        Info.FFDiag(Conv);
        return false;
      }
      APValue Lit;
      if (!Evaluate(Lit, Info, CLE->getInitializer()))
        return false;
      CompleteObject LitObj(LVal.Base, &Lit, Base->getType());
      return extractSubobject(Info, Conv, LitObj, LVal.Designator, RVal, AK);
    } else if (isa<StringLiteral>(Base) || isa<PredefinedExpr>(Base)) {
      // Special-case character extraction so we don't have to construct an
      // APValue for the whole string.
      assert(LVal.Designator.Entries.size() <= 1 &&
             "Can only read characters from string literals");
      if (LVal.Designator.Entries.empty()) {
        // Fail for now for LValue to RValue conversion of an array.
        // (This shouldn't show up in C/C++, but it could be triggered by a
        // weird EvaluateAsRValue call from a tool.)
        Info.FFDiag(Conv);
        return false;
      }
      if (LVal.Designator.isOnePastTheEnd()) {
        if (Info.getLangOpts().CPlusPlus11)
          Info.FFDiag(Conv, diag::note_constexpr_access_past_end) << AK;
        else
          Info.FFDiag(Conv);
        return false;
      }
      uint64_t CharIndex = LVal.Designator.Entries[0].getAsArrayIndex();
      RVal = APValue(extractStringLiteralCharacter(Info, Base, CharIndex));
      return true;
    }
  }

  CompleteObject Obj = findCompleteObject(Info, Conv, AK, LVal, Type);
  return Obj && extractSubobject(Info, Conv, Obj, LVal.Designator, RVal, AK);
}

/// Perform an assignment of Val to LVal. Takes ownership of Val.
static bool handleAssignment(EvalInfo &Info, const Expr *E, const LValue &LVal,
                             QualType LValType, APValue &Val) {
  if (LVal.Designator.Invalid)
    return false;

  if (!Info.getLangOpts().CPlusPlus14) {
    Info.FFDiag(E);
    return false;
  }

  CompleteObject Obj = findCompleteObject(Info, E, AK_Assign, LVal, LValType);
  return Obj && modifySubobject(Info, E, Obj, LVal.Designator, Val);
}

namespace {
struct CompoundAssignSubobjectHandler {
  EvalInfo &Info;
  const Expr *E;
  QualType PromotedLHSType;
  BinaryOperatorKind Opcode;
  const APValue &RHS;

  static const AccessKinds AccessKind = AK_Assign;

  typedef bool result_type;

  bool checkConst(QualType QT) {
    // Assigning to a const object has undefined behavior.
    if (QT.isConstQualified()) {
      Info.FFDiag(E, diag::note_constexpr_modify_const_type) << QT;
      return false;
    }
    return true;
  }

  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    switch (Subobj.getKind()) {
    case APValue::Int:
      return found(Subobj.getInt(), SubobjType);
    case APValue::Float:
      return found(Subobj.getFloat(), SubobjType);
    case APValue::ComplexInt:
    case APValue::ComplexFloat:
      // FIXME: Implement complex compound assignment.
      Info.FFDiag(E);
      return false;
    case APValue::LValue:
      return foundPointer(Subobj, SubobjType);
    default:
      // FIXME: can this happen?
      Info.FFDiag(E);
      return false;
    }
  }
  bool found(APSInt &Value, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;

    if (!SubobjType->isIntegerType()) {
      // We don't support compound assignment on integer-cast-to-pointer
      // values.
      Info.FFDiag(E);
      return false;
    }

    if (RHS.isInt()) {
      APSInt LHS =
          HandleIntToIntCast(Info, E, PromotedLHSType, SubobjType, Value);
      if (!handleIntIntBinOp(Info, E, LHS, Opcode, RHS.getInt(), LHS))
        return false;
      Value = HandleIntToIntCast(Info, E, SubobjType, PromotedLHSType, LHS);
      return true;
    } else if (RHS.isFloat()) {
      APFloat FValue(0.0);
      return HandleIntToFloatCast(Info, E, SubobjType, Value, PromotedLHSType,
                                  FValue) &&
             handleFloatFloatBinOp(Info, E, FValue, Opcode, RHS.getFloat()) &&
             HandleFloatToIntCast(Info, E, PromotedLHSType, FValue, SubobjType,
                                  Value);
    }

    Info.FFDiag(E);
    return false;
  }
  bool found(APFloat &Value, QualType SubobjType) {
    return checkConst(SubobjType) &&
           HandleFloatToFloatCast(Info, E, SubobjType, PromotedLHSType,
                                  Value) &&
           handleFloatFloatBinOp(Info, E, Value, Opcode, RHS.getFloat()) &&
           HandleFloatToFloatCast(Info, E, PromotedLHSType, SubobjType, Value);
  }
  bool foundPointer(APValue &Subobj, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;

    QualType PointeeType;
    if (const PointerType *PT = SubobjType->getAs<PointerType>())
      PointeeType = PT->getPointeeType();

    if (PointeeType.isNull() || !RHS.isInt() ||
        (Opcode != BO_Add && Opcode != BO_Sub)) {
      Info.FFDiag(E);
      return false;
    }

    APSInt Offset = RHS.getInt();
    if (Opcode == BO_Sub)
      negateAsSigned(Offset);

    LValue LVal;
    LVal.setFrom(Info.Ctx, Subobj);
    if (!HandleLValueArrayAdjustment(Info, E, LVal, PointeeType, Offset))
      return false;
    LVal.moveInto(Subobj);
    return true;
  }
};
} // end anonymous namespace

const AccessKinds CompoundAssignSubobjectHandler::AccessKind;

/// Perform a compound assignment of LVal <op>= RVal.
static bool handleCompoundAssignment(
    EvalInfo &Info, const Expr *E,
    const LValue &LVal, QualType LValType, QualType PromotedLValType,
    BinaryOperatorKind Opcode, const APValue &RVal) {
  if (LVal.Designator.Invalid)
    return false;

  if (!Info.getLangOpts().CPlusPlus14) {
    Info.FFDiag(E);
    return false;
  }

  CompleteObject Obj = findCompleteObject(Info, E, AK_Assign, LVal, LValType);
  CompoundAssignSubobjectHandler Handler = { Info, E, PromotedLValType, Opcode,
                                             RVal };
  return Obj && findSubobject(Info, E, Obj, LVal.Designator, Handler);
}

namespace {
struct IncDecSubobjectHandler {
  EvalInfo &Info;
  const UnaryOperator *E;
  AccessKinds AccessKind;
  APValue *Old;

  typedef bool result_type;

  bool checkConst(QualType QT) {
    // Assigning to a const object has undefined behavior.
    if (QT.isConstQualified()) {
      Info.FFDiag(E, diag::note_constexpr_modify_const_type) << QT;
      return false;
    }
    return true;
  }

  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    // Stash the old value. Also clear Old, so we don't clobber it later
    // if we're post-incrementing a complex.
    if (Old) {
      *Old = Subobj;
      Old = nullptr;
    }

    switch (Subobj.getKind()) {
    case APValue::Int:
      return found(Subobj.getInt(), SubobjType);
    case APValue::Float:
      return found(Subobj.getFloat(), SubobjType);
    case APValue::ComplexInt:
      return found(Subobj.getComplexIntReal(),
                   SubobjType->castAs<ComplexType>()->getElementType()
                     .withCVRQualifiers(SubobjType.getCVRQualifiers()));
    case APValue::ComplexFloat:
      return found(Subobj.getComplexFloatReal(),
                   SubobjType->castAs<ComplexType>()->getElementType()
                     .withCVRQualifiers(SubobjType.getCVRQualifiers()));
    case APValue::LValue:
      return foundPointer(Subobj, SubobjType);
    default:
      // FIXME: can this happen?
      Info.FFDiag(E);
      return false;
    }
  }
  bool found(APSInt &Value, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;

    if (!SubobjType->isIntegerType()) {
      // We don't support increment / decrement on integer-cast-to-pointer
      // values.
      Info.FFDiag(E);
      return false;
    }

    if (Old) *Old = APValue(Value);

    // bool arithmetic promotes to int, and the conversion back to bool
    // doesn't reduce mod 2^n, so special-case it.
    if (SubobjType->isBooleanType()) {
      if (AccessKind == AK_Increment)
        Value = 1;
      else
        Value = !Value;
      return true;
    }

    bool WasNegative = Value.isNegative();
    if (AccessKind == AK_Increment) {
      ++Value;

      if (!WasNegative && Value.isNegative() && E->canOverflow()) {
        APSInt ActualValue(Value, /*IsUnsigned*/true);
        return HandleOverflow(Info, E, ActualValue, SubobjType);
      }
    } else {
      --Value;

      if (WasNegative && !Value.isNegative() && E->canOverflow()) {
        unsigned BitWidth = Value.getBitWidth();
        APSInt ActualValue(Value.sext(BitWidth + 1), /*IsUnsigned*/false);
        ActualValue.setBit(BitWidth);
        return HandleOverflow(Info, E, ActualValue, SubobjType);
      }
    }
    return true;
  }
  bool found(APFloat &Value, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;

    if (Old) *Old = APValue(Value);

    APFloat One(Value.getSemantics(), 1);
    if (AccessKind == AK_Increment)
      Value.add(One, APFloat::rmNearestTiesToEven);
    else
      Value.subtract(One, APFloat::rmNearestTiesToEven);
    return true;
  }
  bool foundPointer(APValue &Subobj, QualType SubobjType) {
    if (!checkConst(SubobjType))
      return false;

    QualType PointeeType;
    if (const PointerType *PT = SubobjType->getAs<PointerType>())
      PointeeType = PT->getPointeeType();
    else {
      Info.FFDiag(E);
      return false;
    }

    LValue LVal;
    LVal.setFrom(Info.Ctx, Subobj);
    if (!HandleLValueArrayAdjustment(Info, E, LVal, PointeeType,
                                     AccessKind == AK_Increment ? 1 : -1))
      return false;
    LVal.moveInto(Subobj);
    return true;
  }
};
} // end anonymous namespace

/// Perform an increment or decrement on LVal.
static bool handleIncDec(EvalInfo &Info, const Expr *E, const LValue &LVal,
                         QualType LValType, bool IsIncrement, APValue *Old) {
  if (LVal.Designator.Invalid)
    return false;

  if (!Info.getLangOpts().CPlusPlus14) {
    Info.FFDiag(E);
    return false;
  }

  AccessKinds AK = IsIncrement ? AK_Increment : AK_Decrement;
  CompleteObject Obj = findCompleteObject(Info, E, AK, LVal, LValType);
  IncDecSubobjectHandler Handler = {Info, cast<UnaryOperator>(E), AK, Old};
  return Obj && findSubobject(Info, E, Obj, LVal.Designator, Handler);
}

/// Build an lvalue for the object argument of a member function call.
static bool EvaluateObjectArgument(EvalInfo &Info, const Expr *Object,
                                   LValue &This) {
  if (Object->getType()->isPointerType() && Object->isRValue())
    return EvaluatePointer(Object, This, Info);

  if (Object->isGLValue())
    return EvaluateLValue(Object, This, Info);

  if (Object->getType()->isLiteralType(Info.Ctx))
    return EvaluateTemporary(Object, This, Info);

  Info.FFDiag(Object, diag::note_constexpr_nonliteral) << Object->getType();
  return false;
}

/// HandleMemberPointerAccess - Evaluate a member access operation and build an
/// lvalue referring to the result.
///
/// \param Info - Information about the ongoing evaluation.
/// \param LV - An lvalue referring to the base of the member pointer.
/// \param RHS - The member pointer expression.
/// \param IncludeMember - Specifies whether the member itself is included in
///        the resulting LValue subobject designator. This is not possible when
///        creating a bound member function.
/// \return The field or method declaration to which the member pointer refers,
///         or 0 if evaluation fails.
static const ValueDecl *HandleMemberPointerAccess(EvalInfo &Info,
                                                  QualType LVType,
                                                  LValue &LV,
                                                  const Expr *RHS,
                                                  bool IncludeMember = true) {
  MemberPtr MemPtr;
  if (!EvaluateMemberPointer(RHS, MemPtr, Info))
    return nullptr;

  // C++11 [expr.mptr.oper]p6: If the second operand is the null pointer to
  // member value, the behavior is undefined.
  if (!MemPtr.getDecl()) {
    // FIXME: Specific diagnostic.
    Info.FFDiag(RHS);
    return nullptr;
  }

  if (MemPtr.isDerivedMember()) {
    // This is a member of some derived class. Truncate LV appropriately.
    // The end of the derived-to-base path for the base object must match the
    // derived-to-base path for the member pointer.
    if (LV.Designator.MostDerivedPathLength + MemPtr.Path.size() >
        LV.Designator.Entries.size()) {
      Info.FFDiag(RHS);
      return nullptr;
    }
    unsigned PathLengthToMember =
        LV.Designator.Entries.size() - MemPtr.Path.size();
    for (unsigned I = 0, N = MemPtr.Path.size(); I != N; ++I) {
      const CXXRecordDecl *LVDecl = getAsBaseClass(
          LV.Designator.Entries[PathLengthToMember + I]);
      const CXXRecordDecl *MPDecl = MemPtr.Path[I];
      if (LVDecl->getCanonicalDecl() != MPDecl->getCanonicalDecl()) {
        Info.FFDiag(RHS);
        return nullptr;
      }
    }

    // Truncate the lvalue to the appropriate derived class.
    if (!CastToDerivedClass(Info, RHS, LV, MemPtr.getContainingRecord(),
                            PathLengthToMember))
      return nullptr;
  } else if (!MemPtr.Path.empty()) {
    // Extend the LValue path with the member pointer's path.
    LV.Designator.Entries.reserve(LV.Designator.Entries.size() +
                                  MemPtr.Path.size() + IncludeMember);

    // Walk down to the appropriate base class.
    if (const PointerType *PT = LVType->getAs<PointerType>())
      LVType = PT->getPointeeType();
    const CXXRecordDecl *RD = LVType->getAsCXXRecordDecl();
    assert(RD && "member pointer access on non-class-type expression");
    // The first class in the path is that of the lvalue.
    for (unsigned I = 1, N = MemPtr.Path.size(); I != N; ++I) {
      const CXXRecordDecl *Base = MemPtr.Path[N - I - 1];
      if (!HandleLValueDirectBase(Info, RHS, LV, RD, Base))
        return nullptr;
      RD = Base;
    }
    // Finally cast to the class containing the member.
    if (!HandleLValueDirectBase(Info, RHS, LV, RD,
                                MemPtr.getContainingRecord()))
      return nullptr;
  }

  // Add the member. Note that we cannot build bound member functions here.
  if (IncludeMember) {
    if (const FieldDecl *FD = dyn_cast<FieldDecl>(MemPtr.getDecl())) {
      if (!HandleLValueMember(Info, RHS, LV, FD))
        return nullptr;
    } else if (const IndirectFieldDecl *IFD =
                 dyn_cast<IndirectFieldDecl>(MemPtr.getDecl())) {
      if (!HandleLValueIndirectMember(Info, RHS, LV, IFD))
        return nullptr;
    } else {
      llvm_unreachable("can't construct reference to bound member function");
    }
  }

  return MemPtr.getDecl();
}

static const ValueDecl *HandleMemberPointerAccess(EvalInfo &Info,
                                                  const BinaryOperator *BO,
                                                  LValue &LV,
                                                  bool IncludeMember = true) {
  assert(BO->getOpcode() == BO_PtrMemD || BO->getOpcode() == BO_PtrMemI);

  if (!EvaluateObjectArgument(Info, BO->getLHS(), LV)) {
    if (Info.noteFailure()) {
      MemberPtr MemPtr;
      EvaluateMemberPointer(BO->getRHS(), MemPtr, Info);
    }
    return nullptr;
  }

  return HandleMemberPointerAccess(Info, BO->getLHS()->getType(), LV,
                                   BO->getRHS(), IncludeMember);
}

/// HandleBaseToDerivedCast - Apply the given base-to-derived cast operation on
/// the provided lvalue, which currently refers to the base object.
static bool HandleBaseToDerivedCast(EvalInfo &Info, const CastExpr *E,
                                    LValue &Result) {
  SubobjectDesignator &D = Result.Designator;
  if (D.Invalid || !Result.checkNullPointer(Info, E, CSK_Derived))
    return false;

  QualType TargetQT = E->getType();
  if (const PointerType *PT = TargetQT->getAs<PointerType>())
    TargetQT = PT->getPointeeType();

  // Check this cast lands within the final derived-to-base subobject path.
  if (D.MostDerivedPathLength + E->path_size() > D.Entries.size()) {
    Info.CCEDiag(E, diag::note_constexpr_invalid_downcast)
      << D.MostDerivedType << TargetQT;
    return false;
  }

  // Check the type of the final cast. We don't need to check the path,
  // since a cast can only be formed if the path is unique.
  unsigned NewEntriesSize = D.Entries.size() - E->path_size();
  const CXXRecordDecl *TargetType = TargetQT->getAsCXXRecordDecl();
  const CXXRecordDecl *FinalType;
  if (NewEntriesSize == D.MostDerivedPathLength)
    FinalType = D.MostDerivedType->getAsCXXRecordDecl();
  else
    FinalType = getAsBaseClass(D.Entries[NewEntriesSize - 1]);
  if (FinalType->getCanonicalDecl() != TargetType->getCanonicalDecl()) {
    Info.CCEDiag(E, diag::note_constexpr_invalid_downcast)
      << D.MostDerivedType << TargetQT;
    return false;
  }

  // Truncate the lvalue to the appropriate derived class.
  return CastToDerivedClass(Info, E, Result, TargetType, NewEntriesSize);
}

/// Get the value to use for a default-initialized object of type T.
static APValue getDefaultInitValue(QualType T) {
  if (auto *RD = T->getAsCXXRecordDecl()) {
    if (RD->isUnion())
      return APValue((const FieldDecl*)nullptr);

    APValue Struct(APValue::UninitStruct(), RD->getNumBases(),
                   std::distance(RD->field_begin(), RD->field_end()));

    unsigned Index = 0;
    for (CXXRecordDecl::base_class_const_iterator I = RD->bases_begin(),
           End = RD->bases_end(); I != End; ++I, ++Index)
      Struct.getStructBase(Index) = getDefaultInitValue(I->getType());

    for (const auto *I : RD->fields()) {
      if (I->isUnnamedBitfield())
        continue;
      Struct.getStructField(I->getFieldIndex()) =
          getDefaultInitValue(I->getType());
    }
    return Struct;
  }

  if (auto *AT =
          dyn_cast_or_null<ConstantArrayType>(T->getAsArrayTypeUnsafe())) {
    APValue Array(APValue::UninitArray(), 0, AT->getSize().getZExtValue());
    if (Array.hasArrayFiller())
      Array.getArrayFiller() = getDefaultInitValue(AT->getElementType());
    return Array;
  }

  return APValue::IndeterminateValue();
}

namespace {
enum EvalStmtResult {
  /// Evaluation failed.
  ESR_Failed,
  /// Hit a 'return' statement.
  ESR_Returned,
  /// Evaluation succeeded.
  ESR_Succeeded,
  /// Hit a 'continue' statement.
  ESR_Continue,
  /// Hit a 'break' statement.
  ESR_Break,
  /// Still scanning for 'case' or 'default' statement.
  ESR_CaseNotFound
};
}

static bool EvaluateVarDecl(EvalInfo &Info, const VarDecl *VD) {
  // We don't need to evaluate the initializer for a static local.
  if (!VD->hasLocalStorage())
    return true;

  LValue Result;
  APValue &Val =
      Info.CurrentCall->createTemporary(VD, VD->getType(), true, Result);

  const Expr *InitE = VD->getInit();
  if (!InitE) {
    Val = getDefaultInitValue(VD->getType());
    return true;
  }

  if (InitE->isValueDependent())
    return false;

  if (!EvaluateInPlace(Val, Info, Result, InitE)) {
    // Wipe out any partially-computed value, to allow tracking that this
    // evaluation failed.
    Val = APValue();
    return false;
  }

  return true;
}

static bool EvaluateDecl(EvalInfo &Info, const Decl *D) {
  bool OK = true;

  if (const VarDecl *VD = dyn_cast<VarDecl>(D))
    OK &= EvaluateVarDecl(Info, VD);

  if (const DecompositionDecl *DD = dyn_cast<DecompositionDecl>(D))
    for (auto *BD : DD->bindings())
      if (auto *VD = BD->getHoldingVar())
        OK &= EvaluateDecl(Info, VD);

  return OK;
}


/// Evaluate a condition (either a variable declaration or an expression).
static bool EvaluateCond(EvalInfo &Info, const VarDecl *CondDecl,
                         const Expr *Cond, bool &Result) {
  FullExpressionRAII Scope(Info);
  if (CondDecl && !EvaluateDecl(Info, CondDecl))
    return false;
  if (!EvaluateAsBooleanCondition(Cond, Result, Info))
    return false;
  return Scope.destroy();
}

namespace {
/// A location where the result (returned value) of evaluating a
/// statement should be stored.
struct StmtResult {
  /// The APValue that should be filled in with the returned value.
  APValue &Value;
  /// The location containing the result, if any (used to support RVO).
  const LValue *Slot;
};

struct TempVersionRAII {
  CallStackFrame &Frame;

  TempVersionRAII(CallStackFrame &Frame) : Frame(Frame) {
    Frame.pushTempVersion();
  }

  ~TempVersionRAII() {
    Frame.popTempVersion();
  }
};

}

static EvalStmtResult EvaluateStmt(StmtResult &Result, EvalInfo &Info,
                                   const Stmt *S,
                                   const SwitchCase *SC = nullptr);

/// Evaluate the body of a loop, and translate the result as appropriate.
static EvalStmtResult EvaluateLoopBody(StmtResult &Result, EvalInfo &Info,
                                       const Stmt *Body,
                                       const SwitchCase *Case = nullptr) {
  BlockScopeRAII Scope(Info);

  EvalStmtResult ESR = EvaluateStmt(Result, Info, Body, Case);
  if (ESR != ESR_Failed && ESR != ESR_CaseNotFound && !Scope.destroy())
    ESR = ESR_Failed;

  switch (ESR) {
  case ESR_Break:
    return ESR_Succeeded;
  case ESR_Succeeded:
  case ESR_Continue:
    return ESR_Continue;
  case ESR_Failed:
  case ESR_Returned:
  case ESR_CaseNotFound:
    return ESR;
  }
  llvm_unreachable("Invalid EvalStmtResult!");
}

/// Evaluate a switch statement.
static EvalStmtResult EvaluateSwitch(StmtResult &Result, EvalInfo &Info,
                                     const SwitchStmt *SS) {
  BlockScopeRAII Scope(Info);

  // Evaluate the switch condition.
  APSInt Value;
  {
    if (const Stmt *Init = SS->getInit()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, Init);
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && !Scope.destroy())
          ESR = ESR_Failed;
        return ESR;
      }
    }

    FullExpressionRAII CondScope(Info);
    if (SS->getConditionVariable() &&
        !EvaluateDecl(Info, SS->getConditionVariable()))
      return ESR_Failed;
    if (!EvaluateInteger(SS->getCond(), Value, Info))
      return ESR_Failed;
    if (!CondScope.destroy())
      return ESR_Failed;
  }

  // Find the switch case corresponding to the value of the condition.
  // FIXME: Cache this lookup.
  const SwitchCase *Found = nullptr;
  for (const SwitchCase *SC = SS->getSwitchCaseList(); SC;
       SC = SC->getNextSwitchCase()) {
    if (isa<DefaultStmt>(SC)) {
      Found = SC;
      continue;
    }

    const CaseStmt *CS = cast<CaseStmt>(SC);
    APSInt LHS = CS->getLHS()->EvaluateKnownConstInt(Info.Ctx);
    APSInt RHS = CS->getRHS() ? CS->getRHS()->EvaluateKnownConstInt(Info.Ctx)
                              : LHS;
    if (LHS <= Value && Value <= RHS) {
      Found = SC;
      break;
    }
  }

  if (!Found)
    return Scope.destroy() ? ESR_Succeeded : ESR_Failed;

  // Search the switch body for the switch case and evaluate it from there.
  EvalStmtResult ESR = EvaluateStmt(Result, Info, SS->getBody(), Found);
  if (ESR != ESR_Failed && ESR != ESR_CaseNotFound && !Scope.destroy())
    return ESR_Failed;

  switch (ESR) {
  case ESR_Break:
    return ESR_Succeeded;
  case ESR_Succeeded:
  case ESR_Continue:
  case ESR_Failed:
  case ESR_Returned:
    return ESR;
  case ESR_CaseNotFound:
    // This can only happen if the switch case is nested within a statement
    // expression. We have no intention of supporting that.
    Info.FFDiag(Found->getBeginLoc(),
                diag::note_constexpr_stmt_expr_unsupported);
    return ESR_Failed;
  }
  llvm_unreachable("Invalid EvalStmtResult!");
}

// Evaluate a statement.
static EvalStmtResult EvaluateStmt(StmtResult &Result, EvalInfo &Info,
                                   const Stmt *S, const SwitchCase *Case) {
  if (!Info.nextStep(S))
    return ESR_Failed;

  // If we're hunting down a 'case' or 'default' label, recurse through
  // substatements until we hit the label.
  if (Case) {
    switch (S->getStmtClass()) {
    case Stmt::CompoundStmtClass:
      // FIXME: Precompute which substatement of a compound statement we
      // would jump to, and go straight there rather than performing a
      // linear scan each time.
    case Stmt::LabelStmtClass:
    case Stmt::AttributedStmtClass:
    case Stmt::DoStmtClass:
      break;

    case Stmt::CaseStmtClass:
    case Stmt::DefaultStmtClass:
      if (Case == S)
        Case = nullptr;
      break;

    case Stmt::IfStmtClass: {
      // FIXME: Precompute which side of an 'if' we would jump to, and go
      // straight there rather than scanning both sides.
      const IfStmt *IS = cast<IfStmt>(S);

      // Wrap the evaluation in a block scope, in case it's a DeclStmt
      // preceded by our switch label.
      BlockScopeRAII Scope(Info);

      // Step into the init statement in case it brings an (uninitialized)
      // variable into scope.
      if (const Stmt *Init = IS->getInit()) {
        EvalStmtResult ESR = EvaluateStmt(Result, Info, Init, Case);
        if (ESR != ESR_CaseNotFound) {
          assert(ESR != ESR_Succeeded);
          return ESR;
        }
      }

      // Condition variable must be initialized if it exists.
      // FIXME: We can skip evaluating the body if there's a condition
      // variable, as there can't be any case labels within it.
      // (The same is true for 'for' statements.)

      EvalStmtResult ESR = EvaluateStmt(Result, Info, IS->getThen(), Case);
      if (ESR == ESR_Failed)
        return ESR;
      if (ESR != ESR_CaseNotFound)
        return Scope.destroy() ? ESR : ESR_Failed;
      if (!IS->getElse())
        return ESR_CaseNotFound;

      ESR = EvaluateStmt(Result, Info, IS->getElse(), Case);
      if (ESR == ESR_Failed)
        return ESR;
      if (ESR != ESR_CaseNotFound)
        return Scope.destroy() ? ESR : ESR_Failed;
      return ESR_CaseNotFound;
    }

    case Stmt::WhileStmtClass: {
      EvalStmtResult ESR =
          EvaluateLoopBody(Result, Info, cast<WhileStmt>(S)->getBody(), Case);
      if (ESR != ESR_Continue)
        return ESR;
      break;
    }

    case Stmt::ForStmtClass: {
      const ForStmt *FS = cast<ForStmt>(S);
      BlockScopeRAII Scope(Info);

      // Step into the init statement in case it brings an (uninitialized)
      // variable into scope.
      if (const Stmt *Init = FS->getInit()) {
        EvalStmtResult ESR = EvaluateStmt(Result, Info, Init, Case);
        if (ESR != ESR_CaseNotFound) {
          assert(ESR != ESR_Succeeded);
          return ESR;
        }
      }

      EvalStmtResult ESR =
          EvaluateLoopBody(Result, Info, FS->getBody(), Case);
      if (ESR != ESR_Continue)
        return ESR;
      if (FS->getInc()) {
        FullExpressionRAII IncScope(Info);
        if (!EvaluateIgnoredValue(Info, FS->getInc()) || !IncScope.destroy())
          return ESR_Failed;
      }
      break;
    }

    case Stmt::DeclStmtClass: {
      // Start the lifetime of any uninitialized variables we encounter. They
      // might be used by the selected branch of the switch.
      const DeclStmt *DS = cast<DeclStmt>(S);
      for (const auto *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (VD->hasLocalStorage() && !VD->getInit())
            if (!EvaluateVarDecl(Info, VD))
              return ESR_Failed;
          // FIXME: If the variable has initialization that can't be jumped
          // over, bail out of any immediately-surrounding compound-statement
          // too. There can't be any case labels here.
        }
      }
      return ESR_CaseNotFound;
    }

    default:
      return ESR_CaseNotFound;
    }
  }

  switch (S->getStmtClass()) {
  default:
    if (const Expr *E = dyn_cast<Expr>(S)) {
      // Don't bother evaluating beyond an expression-statement which couldn't
      // be evaluated.
      // FIXME: Do we need the FullExpressionRAII object here?
      // VisitExprWithCleanups should create one when necessary.
      FullExpressionRAII Scope(Info);
      if (!EvaluateIgnoredValue(Info, E) || !Scope.destroy())
        return ESR_Failed;
      return ESR_Succeeded;
    }

    Info.FFDiag(S->getBeginLoc());
    return ESR_Failed;

  case Stmt::NullStmtClass:
    return ESR_Succeeded;

  case Stmt::DeclStmtClass: {
    const DeclStmt *DS = cast<DeclStmt>(S);
    for (const auto *D : DS->decls()) {
      // Each declaration initialization is its own full-expression.
      FullExpressionRAII Scope(Info);
      if (!EvaluateDecl(Info, D) && !Info.noteFailure())
        return ESR_Failed;
      if (!Scope.destroy())
        return ESR_Failed;
    }
    return ESR_Succeeded;
  }

  case Stmt::ReturnStmtClass: {
    const Expr *RetExpr = cast<ReturnStmt>(S)->getRetValue();
    FullExpressionRAII Scope(Info);
    if (RetExpr &&
        !(Result.Slot
              ? EvaluateInPlace(Result.Value, Info, *Result.Slot, RetExpr)
              : Evaluate(Result.Value, Info, RetExpr)))
      return ESR_Failed;
    return Scope.destroy() ? ESR_Returned : ESR_Failed;
  }

  case Stmt::CompoundStmtClass: {
    BlockScopeRAII Scope(Info);

    const CompoundStmt *CS = cast<CompoundStmt>(S);
    for (const auto *BI : CS->body()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, BI, Case);
      if (ESR == ESR_Succeeded)
        Case = nullptr;
      else if (ESR != ESR_CaseNotFound) {
        if (ESR != ESR_Failed && !Scope.destroy())
          return ESR_Failed;
        return ESR;
      }
    }
    if (Case)
      return ESR_CaseNotFound;
    return Scope.destroy() ? ESR_Succeeded : ESR_Failed;
  }

  case Stmt::IfStmtClass: {
    const IfStmt *IS = cast<IfStmt>(S);

    // Evaluate the condition, as either a var decl or as an expression.
    BlockScopeRAII Scope(Info);
    if (const Stmt *Init = IS->getInit()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, Init);
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && !Scope.destroy())
          return ESR_Failed;
        return ESR;
      }
    }
    bool Cond;
    if (!EvaluateCond(Info, IS->getConditionVariable(), IS->getCond(), Cond))
      return ESR_Failed;

    if (const Stmt *SubStmt = Cond ? IS->getThen() : IS->getElse()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, SubStmt);
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && !Scope.destroy())
          return ESR_Failed;
        return ESR;
      }
    }
    return Scope.destroy() ? ESR_Succeeded : ESR_Failed;
  }

  case Stmt::WhileStmtClass: {
    const WhileStmt *WS = cast<WhileStmt>(S);
    while (true) {
      BlockScopeRAII Scope(Info);
      bool Continue;
      if (!EvaluateCond(Info, WS->getConditionVariable(), WS->getCond(),
                        Continue))
        return ESR_Failed;
      if (!Continue)
        break;

      EvalStmtResult ESR = EvaluateLoopBody(Result, Info, WS->getBody());
      if (ESR != ESR_Continue) {
        if (ESR != ESR_Failed && !Scope.destroy())
          return ESR_Failed;
        return ESR;
      }
      if (!Scope.destroy())
        return ESR_Failed;
    }
    return ESR_Succeeded;
  }

  case Stmt::DoStmtClass: {
    const DoStmt *DS = cast<DoStmt>(S);
    bool Continue;
    do {
      EvalStmtResult ESR = EvaluateLoopBody(Result, Info, DS->getBody(), Case);
      if (ESR != ESR_Continue)
        return ESR;
      Case = nullptr;

      FullExpressionRAII CondScope(Info);
      if (!EvaluateAsBooleanCondition(DS->getCond(), Continue, Info) ||
          !CondScope.destroy())
        return ESR_Failed;
    } while (Continue);
    return ESR_Succeeded;
  }

  case Stmt::ForStmtClass: {
    const ForStmt *FS = cast<ForStmt>(S);
    BlockScopeRAII ForScope(Info);
    if (FS->getInit()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, FS->getInit());
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && !ForScope.destroy())
          return ESR_Failed;
        return ESR;
      }
    }
    while (true) {
      BlockScopeRAII IterScope(Info);
      bool Continue = true;
      if (FS->getCond() && !EvaluateCond(Info, FS->getConditionVariable(),
                                         FS->getCond(), Continue))
        return ESR_Failed;
      if (!Continue)
        break;

      EvalStmtResult ESR = EvaluateLoopBody(Result, Info, FS->getBody());
      if (ESR != ESR_Continue) {
        if (ESR != ESR_Failed && (!IterScope.destroy() || !ForScope.destroy()))
          return ESR_Failed;
        return ESR;
      }

      if (FS->getInc()) {
        FullExpressionRAII IncScope(Info);
        if (!EvaluateIgnoredValue(Info, FS->getInc()) || !IncScope.destroy())
          return ESR_Failed;
      }

      if (!IterScope.destroy())
        return ESR_Failed;
    }
    return ForScope.destroy() ? ESR_Succeeded : ESR_Failed;
  }

  case Stmt::CXXForRangeStmtClass: {
    const CXXForRangeStmt *FS = cast<CXXForRangeStmt>(S);
    BlockScopeRAII Scope(Info);

    // Evaluate the init-statement if present.
    if (FS->getInit()) {
      EvalStmtResult ESR = EvaluateStmt(Result, Info, FS->getInit());
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && !Scope.destroy())
          return ESR_Failed;
        return ESR;
      }
    }

    // Initialize the __range variable.
    EvalStmtResult ESR = EvaluateStmt(Result, Info, FS->getRangeStmt());
    if (ESR != ESR_Succeeded) {
      if (ESR != ESR_Failed && !Scope.destroy())
        return ESR_Failed;
      return ESR;
    }

    // Create the __begin and __end iterators.
    ESR = EvaluateStmt(Result, Info, FS->getBeginStmt());
    if (ESR != ESR_Succeeded) {
      if (ESR != ESR_Failed && !Scope.destroy())
        return ESR_Failed;
      return ESR;
    }
    ESR = EvaluateStmt(Result, Info, FS->getEndStmt());
    if (ESR != ESR_Succeeded) {
      if (ESR != ESR_Failed && !Scope.destroy())
        return ESR_Failed;
      return ESR;
    }

    while (true) {
      // Condition: __begin != __end.
      {
        bool Continue = true;
        FullExpressionRAII CondExpr(Info);
        if (!EvaluateAsBooleanCondition(FS->getCond(), Continue, Info))
          return ESR_Failed;
        if (!Continue)
          break;
      }

      // User's variable declaration, initialized by *__begin.
      BlockScopeRAII InnerScope(Info);
      ESR = EvaluateStmt(Result, Info, FS->getLoopVarStmt());
      if (ESR != ESR_Succeeded) {
        if (ESR != ESR_Failed && (!InnerScope.destroy() || !Scope.destroy()))
          return ESR_Failed;
        return ESR;
      }

      // Loop body.
      ESR = EvaluateLoopBody(Result, Info, FS->getBody());
      if (ESR != ESR_Continue) {
        if (ESR != ESR_Failed && (!InnerScope.destroy() || !Scope.destroy()))
          return ESR_Failed;
        return ESR;
      }

      // Increment: ++__begin
      if (!EvaluateIgnoredValue(Info, FS->getInc()))
        return ESR_Failed;

      if (!InnerScope.destroy())
        return ESR_Failed;
    }

    return Scope.destroy() ? ESR_Succeeded : ESR_Failed;
  }

  case Stmt::SwitchStmtClass:
    return EvaluateSwitch(Result, Info, cast<SwitchStmt>(S));

  case Stmt::ContinueStmtClass:
    return ESR_Continue;

  case Stmt::BreakStmtClass:
    return ESR_Break;

  case Stmt::LabelStmtClass:
    return EvaluateStmt(Result, Info, cast<LabelStmt>(S)->getSubStmt(), Case);

  case Stmt::AttributedStmtClass:
    // As a general principle, C++11 attributes can be ignored without
    // any semantic impact.
    return EvaluateStmt(Result, Info, cast<AttributedStmt>(S)->getSubStmt(),
                        Case);

  case Stmt::CaseStmtClass:
  case Stmt::DefaultStmtClass:
    return EvaluateStmt(Result, Info, cast<SwitchCase>(S)->getSubStmt(), Case);
  case Stmt::CXXTryStmtClass:
    // Evaluate try blocks by evaluating all sub statements.
    return EvaluateStmt(Result, Info, cast<CXXTryStmt>(S)->getTryBlock(), Case);
  }
}

/// CheckTrivialDefaultConstructor - Check whether a constructor is a trivial
/// default constructor. If so, we'll fold it whether or not it's marked as
/// constexpr. If it is marked as constexpr, we will never implicitly define it,
/// so we need special handling.
static bool CheckTrivialDefaultConstructor(EvalInfo &Info, SourceLocation Loc,
                                           const CXXConstructorDecl *CD,
                                           bool IsValueInitialization) {
  if (!CD->isTrivial() || !CD->isDefaultConstructor())
    return false;

  // Value-initialization does not call a trivial default constructor, so such a
  // call is a core constant expression whether or not the constructor is
  // constexpr.
  if (!CD->isConstexpr() && !IsValueInitialization) {
    if (Info.getLangOpts().CPlusPlus11) {
      // FIXME: If DiagDecl is an implicitly-declared special member function,
      // we should be much more explicit about why it's not constexpr.
      Info.CCEDiag(Loc, diag::note_constexpr_invalid_function, 1)
        << /*IsConstexpr*/0 << /*IsConstructor*/1 << CD;
      Info.Note(CD->getLocation(), diag::note_declared_at);
    } else {
      Info.CCEDiag(Loc, diag::note_invalid_subexpr_in_const_expr);
    }
  }
  return true;
}

/// CheckConstexprFunction - Check that a function can be called in a constant
/// expression.
static bool CheckConstexprFunction(EvalInfo &Info, SourceLocation CallLoc,
                                   const FunctionDecl *Declaration,
                                   const FunctionDecl *Definition,
                                   const Stmt *Body) {
  // Potential constant expressions can contain calls to declared, but not yet
  // defined, constexpr functions.
  if (Info.checkingPotentialConstantExpression() && !Definition &&
      Declaration->isConstexpr())
    return false;

  // Bail out if the function declaration itself is invalid.  We will
  // have produced a relevant diagnostic while parsing it, so just
  // note the problematic sub-expression.
  if (Declaration->isInvalidDecl()) {
    Info.FFDiag(CallLoc, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  // DR1872: An instantiated virtual constexpr function can't be called in a
  // constant expression (prior to C++20). We can still constant-fold such a
  // call.
  if (!Info.Ctx.getLangOpts().CPlusPlus2a && isa<CXXMethodDecl>(Declaration) &&
      cast<CXXMethodDecl>(Declaration)->isVirtual())
    Info.CCEDiag(CallLoc, diag::note_constexpr_virtual_call);

  if (Definition && Definition->isInvalidDecl()) {
    Info.FFDiag(CallLoc, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  // Can we evaluate this function call?
  if (Definition && Definition->isConstexpr() && Body)
    return true;

  if (Info.getLangOpts().CPlusPlus11) {
    const FunctionDecl *DiagDecl = Definition ? Definition : Declaration;

    // If this function is not constexpr because it is an inherited
    // non-constexpr constructor, diagnose that directly.
    auto *CD = dyn_cast<CXXConstructorDecl>(DiagDecl);
    if (CD && CD->isInheritingConstructor()) {
      auto *Inherited = CD->getInheritedConstructor().getConstructor();
      if (!Inherited->isConstexpr())
        DiagDecl = CD = Inherited;
    }

    // FIXME: If DiagDecl is an implicitly-declared special member function
    // or an inheriting constructor, we should be much more explicit about why
    // it's not constexpr.
    if (CD && CD->isInheritingConstructor())
      Info.FFDiag(CallLoc, diag::note_constexpr_invalid_inhctor, 1)
        << CD->getInheritedConstructor().getConstructor()->getParent();
    else
      Info.FFDiag(CallLoc, diag::note_constexpr_invalid_function, 1)
        << DiagDecl->isConstexpr() << (bool)CD << DiagDecl;
    Info.Note(DiagDecl->getLocation(), diag::note_declared_at);
  } else {
    Info.FFDiag(CallLoc, diag::note_invalid_subexpr_in_const_expr);
  }
  return false;
}

namespace {
struct CheckDynamicTypeHandler {
  AccessKinds AccessKind;
  typedef bool result_type;
  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) { return true; }
  bool found(APSInt &Value, QualType SubobjType) { return true; }
  bool found(APFloat &Value, QualType SubobjType) { return true; }
};
} // end anonymous namespace

/// Check that we can access the notional vptr of an object / determine its
/// dynamic type.
static bool checkDynamicType(EvalInfo &Info, const Expr *E, const LValue &This,
                             AccessKinds AK, bool Polymorphic) {
  if (This.Designator.Invalid)
    return false;

  CompleteObject Obj = findCompleteObject(Info, E, AK, This, QualType());

  if (!Obj)
    return false;

  if (!Obj.Value) {
    // The object is not usable in constant expressions, so we can't inspect
    // its value to see if it's in-lifetime or what the active union members
    // are. We can still check for a one-past-the-end lvalue.
    if (This.Designator.isOnePastTheEnd() ||
        This.Designator.isMostDerivedAnUnsizedArray()) {
      Info.FFDiag(E, This.Designator.isOnePastTheEnd()
                         ? diag::note_constexpr_access_past_end
                         : diag::note_constexpr_access_unsized_array)
          << AK;
      return false;
    } else if (Polymorphic) {
      // Conservatively refuse to perform a polymorphic operation if we would
      // not be able to read a notional 'vptr' value.
      APValue Val;
      This.moveInto(Val);
      QualType StarThisType =
          Info.Ctx.getLValueReferenceType(This.Designator.getType(Info.Ctx));
      Info.FFDiag(E, diag::note_constexpr_polymorphic_unknown_dynamic_type)
          << AK << Val.getAsString(Info.Ctx, StarThisType);
      return false;
    }
    return true;
  }

  CheckDynamicTypeHandler Handler{AK};
  return Obj && findSubobject(Info, E, Obj, This.Designator, Handler);
}

/// Check that the pointee of the 'this' pointer in a member function call is
/// either within its lifetime or in its period of construction or destruction.
static bool
checkNonVirtualMemberCallThisPointer(EvalInfo &Info, const Expr *E,
                                     const LValue &This,
                                     const CXXMethodDecl *NamedMember) {
  return checkDynamicType(
      Info, E, This,
      isa<CXXDestructorDecl>(NamedMember) ? AK_Destroy : AK_MemberCall, false);
}

struct DynamicType {
  /// The dynamic class type of the object.
  const CXXRecordDecl *Type;
  /// The corresponding path length in the lvalue.
  unsigned PathLength;
};

static const CXXRecordDecl *getBaseClassType(SubobjectDesignator &Designator,
                                             unsigned PathLength) {
  assert(PathLength >= Designator.MostDerivedPathLength && PathLength <=
      Designator.Entries.size() && "invalid path length");
  return (PathLength == Designator.MostDerivedPathLength)
             ? Designator.MostDerivedType->getAsCXXRecordDecl()
             : getAsBaseClass(Designator.Entries[PathLength - 1]);
}

/// Determine the dynamic type of an object.
static Optional<DynamicType> ComputeDynamicType(EvalInfo &Info, const Expr *E,
                                                LValue &This, AccessKinds AK) {
  // If we don't have an lvalue denoting an object of class type, there is no
  // meaningful dynamic type. (We consider objects of non-class type to have no
  // dynamic type.)
  if (!checkDynamicType(Info, E, This, AK, true))
    return None;

  // Refuse to compute a dynamic type in the presence of virtual bases. This
  // shouldn't happen other than in constant-folding situations, since literal
  // types can't have virtual bases.
  //
  // Note that consumers of DynamicType assume that the type has no virtual
  // bases, and will need modifications if this restriction is relaxed.
  const CXXRecordDecl *Class =
      This.Designator.MostDerivedType->getAsCXXRecordDecl();
  if (!Class || Class->getNumVBases()) {
    Info.FFDiag(E);
    return None;
  }

  // FIXME: For very deep class hierarchies, it might be beneficial to use a
  // binary search here instead. But the overwhelmingly common case is that
  // we're not in the middle of a constructor, so it probably doesn't matter
  // in practice.
  ArrayRef<APValue::LValuePathEntry> Path = This.Designator.Entries;
  for (unsigned PathLength = This.Designator.MostDerivedPathLength;
       PathLength <= Path.size(); ++PathLength) {
    switch (Info.isEvaluatingCtorDtor(This.getLValueBase(),
                                      Path.slice(0, PathLength))) {
    case ConstructionPhase::Bases:
    case ConstructionPhase::DestroyingBases:
      // We're constructing or destroying a base class. This is not the dynamic
      // type.
      break;

    case ConstructionPhase::None:
    case ConstructionPhase::AfterBases:
    case ConstructionPhase::Destroying:
      // We've finished constructing the base classes and not yet started
      // destroying them again, so this is the dynamic type.
      return DynamicType{getBaseClassType(This.Designator, PathLength),
                         PathLength};
    }
  }

  // CWG issue 1517: we're constructing a base class of the object described by
  // 'This', so that object has not yet begun its period of construction and
  // any polymorphic operation on it results in undefined behavior.
  Info.FFDiag(E);
  return None;
}

/// Perform virtual dispatch.
static const CXXMethodDecl *HandleVirtualDispatch(
    EvalInfo &Info, const Expr *E, LValue &This, const CXXMethodDecl *Found,
    llvm::SmallVectorImpl<QualType> &CovariantAdjustmentPath) {
  Optional<DynamicType> DynType = ComputeDynamicType(
      Info, E, This,
      isa<CXXDestructorDecl>(Found) ? AK_Destroy : AK_MemberCall);
  if (!DynType)
    return nullptr;

  // Find the final overrider. It must be declared in one of the classes on the
  // path from the dynamic type to the static type.
  // FIXME: If we ever allow literal types to have virtual base classes, that
  // won't be true.
  const CXXMethodDecl *Callee = Found;
  unsigned PathLength = DynType->PathLength;
  for (/**/; PathLength <= This.Designator.Entries.size(); ++PathLength) {
    const CXXRecordDecl *Class = getBaseClassType(This.Designator, PathLength);
    const CXXMethodDecl *Overrider =
        Found->getCorrespondingMethodDeclaredInClass(Class, false);
    if (Overrider) {
      Callee = Overrider;
      break;
    }
  }

  // C++2a [class.abstract]p6:
  //   the effect of making a virtual call to a pure virtual function [...] is
  //   undefined
  if (Callee->isPure()) {
    Info.FFDiag(E, diag::note_constexpr_pure_virtual_call, 1) << Callee;
    Info.Note(Callee->getLocation(), diag::note_declared_at);
    return nullptr;
  }

  // If necessary, walk the rest of the path to determine the sequence of
  // covariant adjustment steps to apply.
  if (!Info.Ctx.hasSameUnqualifiedType(Callee->getReturnType(),
                                       Found->getReturnType())) {
    CovariantAdjustmentPath.push_back(Callee->getReturnType());
    for (unsigned CovariantPathLength = PathLength + 1;
         CovariantPathLength != This.Designator.Entries.size();
         ++CovariantPathLength) {
      const CXXRecordDecl *NextClass =
          getBaseClassType(This.Designator, CovariantPathLength);
      const CXXMethodDecl *Next =
          Found->getCorrespondingMethodDeclaredInClass(NextClass, false);
      if (Next && !Info.Ctx.hasSameUnqualifiedType(
                      Next->getReturnType(), CovariantAdjustmentPath.back()))
        CovariantAdjustmentPath.push_back(Next->getReturnType());
    }
    if (!Info.Ctx.hasSameUnqualifiedType(Found->getReturnType(),
                                         CovariantAdjustmentPath.back()))
      CovariantAdjustmentPath.push_back(Found->getReturnType());
  }

  // Perform 'this' adjustment.
  if (!CastToDerivedClass(Info, E, This, Callee->getParent(), PathLength))
    return nullptr;

  return Callee;
}

/// Perform the adjustment from a value returned by a virtual function to
/// a value of the statically expected type, which may be a pointer or
/// reference to a base class of the returned type.
static bool HandleCovariantReturnAdjustment(EvalInfo &Info, const Expr *E,
                                            APValue &Result,
                                            ArrayRef<QualType> Path) {
  assert(Result.isLValue() &&
         "unexpected kind of APValue for covariant return");
  if (Result.isNullPointer())
    return true;

  LValue LVal;
  LVal.setFrom(Info.Ctx, Result);

  const CXXRecordDecl *OldClass = Path[0]->getPointeeCXXRecordDecl();
  for (unsigned I = 1; I != Path.size(); ++I) {
    const CXXRecordDecl *NewClass = Path[I]->getPointeeCXXRecordDecl();
    assert(OldClass && NewClass && "unexpected kind of covariant return");
    if (OldClass != NewClass &&
        !CastToBaseClass(Info, E, LVal, OldClass, NewClass))
      return false;
    OldClass = NewClass;
  }

  LVal.moveInto(Result);
  return true;
}

/// Determine whether \p Base, which is known to be a direct base class of
/// \p Derived, is a public base class.
static bool isBaseClassPublic(const CXXRecordDecl *Derived,
                              const CXXRecordDecl *Base) {
  for (const CXXBaseSpecifier &BaseSpec : Derived->bases()) {
    auto *BaseClass = BaseSpec.getType()->getAsCXXRecordDecl();
    if (BaseClass && declaresSameEntity(BaseClass, Base))
      return BaseSpec.getAccessSpecifier() == AS_public;
  }
  llvm_unreachable("Base is not a direct base of Derived");
}

/// Apply the given dynamic cast operation on the provided lvalue.
///
/// This implements the hard case of dynamic_cast, requiring a "runtime check"
/// to find a suitable target subobject.
static bool HandleDynamicCast(EvalInfo &Info, const ExplicitCastExpr *E,
                              LValue &Ptr) {
  // We can't do anything with a non-symbolic pointer value.
  SubobjectDesignator &D = Ptr.Designator;
  if (D.Invalid)
    return false;

  // C++ [expr.dynamic.cast]p6:
  //   If v is a null pointer value, the result is a null pointer value.
  if (Ptr.isNullPointer() && !E->isGLValue())
    return true;

  // For all the other cases, we need the pointer to point to an object within
  // its lifetime / period of construction / destruction, and we need to know
  // its dynamic type.
  Optional<DynamicType> DynType =
      ComputeDynamicType(Info, E, Ptr, AK_DynamicCast);
  if (!DynType)
    return false;

  // C++ [expr.dynamic.cast]p7:
  //   If T is "pointer to cv void", then the result is a pointer to the most
  //   derived object
  if (E->getType()->isVoidPointerType())
    return CastToDerivedClass(Info, E, Ptr, DynType->Type, DynType->PathLength);

  const CXXRecordDecl *C = E->getTypeAsWritten()->getPointeeCXXRecordDecl();
  assert(C && "dynamic_cast target is not void pointer nor class");
  CanQualType CQT = Info.Ctx.getCanonicalType(Info.Ctx.getRecordType(C));

  auto RuntimeCheckFailed = [&] (CXXBasePaths *Paths) {
    // C++ [expr.dynamic.cast]p9:
    if (!E->isGLValue()) {
      //   The value of a failed cast to pointer type is the null pointer value
      //   of the required result type.
      Ptr.setNull(Info.Ctx, E->getType());
      return true;
    }

    //   A failed cast to reference type throws [...] std::bad_cast.
    unsigned DiagKind;
    if (!Paths && (declaresSameEntity(DynType->Type, C) ||
                   DynType->Type->isDerivedFrom(C)))
      DiagKind = 0;
    else if (!Paths || Paths->begin() == Paths->end())
      DiagKind = 1;
    else if (Paths->isAmbiguous(CQT))
      DiagKind = 2;
    else {
      assert(Paths->front().Access != AS_public && "why did the cast fail?");
      DiagKind = 3;
    }
    Info.FFDiag(E, diag::note_constexpr_dynamic_cast_to_reference_failed)
        << DiagKind << Ptr.Designator.getType(Info.Ctx)
        << Info.Ctx.getRecordType(DynType->Type)
        << E->getType().getUnqualifiedType();
    return false;
  };

  // Runtime check, phase 1:
  //   Walk from the base subobject towards the derived object looking for the
  //   target type.
  for (int PathLength = Ptr.Designator.Entries.size();
       PathLength >= (int)DynType->PathLength; --PathLength) {
    const CXXRecordDecl *Class = getBaseClassType(Ptr.Designator, PathLength);
    if (declaresSameEntity(Class, C))
      return CastToDerivedClass(Info, E, Ptr, Class, PathLength);
    // We can only walk across public inheritance edges.
    if (PathLength > (int)DynType->PathLength &&
        !isBaseClassPublic(getBaseClassType(Ptr.Designator, PathLength - 1),
                           Class))
      return RuntimeCheckFailed(nullptr);
  }

  // Runtime check, phase 2:
  //   Search the dynamic type for an unambiguous public base of type C.
  CXXBasePaths Paths(/*FindAmbiguities=*/true,
                     /*RecordPaths=*/true, /*DetectVirtual=*/false);
  if (DynType->Type->isDerivedFrom(C, Paths) && !Paths.isAmbiguous(CQT) &&
      Paths.front().Access == AS_public) {
    // Downcast to the dynamic type...
    if (!CastToDerivedClass(Info, E, Ptr, DynType->Type, DynType->PathLength))
      return false;
    // ... then upcast to the chosen base class subobject.
    for (CXXBasePathElement &Elem : Paths.front())
      if (!HandleLValueBase(Info, E, Ptr, Elem.Class, Elem.Base))
        return false;
    return true;
  }

  // Otherwise, the runtime check fails.
  return RuntimeCheckFailed(&Paths);
}

namespace {
struct StartLifetimeOfUnionMemberHandler {
  const FieldDecl *Field;

  static const AccessKinds AccessKind = AK_Assign;

  typedef bool result_type;
  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    // We are supposed to perform no initialization but begin the lifetime of
    // the object. We interpret that as meaning to do what default
    // initialization of the object would do if all constructors involved were
    // trivial:
    //  * All base, non-variant member, and array element subobjects' lifetimes
    //    begin
    //  * No variant members' lifetimes begin
    //  * All scalar subobjects whose lifetimes begin have indeterminate values
    assert(SubobjType->isUnionType());
    if (!declaresSameEntity(Subobj.getUnionField(), Field) ||
        !Subobj.getUnionValue().hasValue())
      Subobj.setUnion(Field, getDefaultInitValue(Field->getType()));
    return true;
  }
  bool found(APSInt &Value, QualType SubobjType) {
    llvm_unreachable("wrong value kind for union object");
  }
  bool found(APFloat &Value, QualType SubobjType) {
    llvm_unreachable("wrong value kind for union object");
  }
};
} // end anonymous namespace

const AccessKinds StartLifetimeOfUnionMemberHandler::AccessKind;

/// Handle a builtin simple-assignment or a call to a trivial assignment
/// operator whose left-hand side might involve a union member access. If it
/// does, implicitly start the lifetime of any accessed union elements per
/// C++20 [class.union]5.
static bool HandleUnionActiveMemberChange(EvalInfo &Info, const Expr *LHSExpr,
                                          const LValue &LHS) {
  if (LHS.InvalidBase || LHS.Designator.Invalid)
    return false;

  llvm::SmallVector<std::pair<unsigned, const FieldDecl*>, 4> UnionPathLengths;
  // C++ [class.union]p5:
  //   define the set S(E) of subexpressions of E as follows:
  unsigned PathLength = LHS.Designator.Entries.size();
  for (const Expr *E = LHSExpr; E != nullptr;) {
    //   -- If E is of the form A.B, S(E) contains the elements of S(A)...
    if (auto *ME = dyn_cast<MemberExpr>(E)) {
      auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      // Note that we can't implicitly start the lifetime of a reference,
      // so we don't need to proceed any further if we reach one.
      if (!FD || FD->getType()->isReferenceType())
        break;

      //    ... and also contains A.B if B names a union member ...
      if (FD->getParent()->isUnion()) {
        //    ... of a non-class, non-array type, or of a class type with a
        //    trivial default constructor that is not deleted, or an array of
        //    such types.
        auto *RD =
            FD->getType()->getBaseElementTypeUnsafe()->getAsCXXRecordDecl();
        if (!RD || RD->hasTrivialDefaultConstructor())
          UnionPathLengths.push_back({PathLength - 1, FD});
      }

      E = ME->getBase();
      --PathLength;
      assert(declaresSameEntity(FD,
                                LHS.Designator.Entries[PathLength]
                                    .getAsBaseOrMember().getPointer()));

      //   -- If E is of the form A[B] and is interpreted as a built-in array
      //      subscripting operator, S(E) is [S(the array operand, if any)].
    } else if (auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      // Step over an ArrayToPointerDecay implicit cast.
      auto *Base = ASE->getBase()->IgnoreImplicit();
      if (!Base->getType()->isArrayType())
        break;

      E = Base;
      --PathLength;

    } else if (auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
      // Step over a derived-to-base conversion.
      E = ICE->getSubExpr();
      if (ICE->getCastKind() == CK_NoOp)
        continue;
      if (ICE->getCastKind() != CK_DerivedToBase &&
          ICE->getCastKind() != CK_UncheckedDerivedToBase)
        break;
      // Walk path backwards as we walk up from the base to the derived class.
      for (const CXXBaseSpecifier *Elt : llvm::reverse(ICE->path())) {
        --PathLength;
        (void)Elt;
        assert(declaresSameEntity(Elt->getType()->getAsCXXRecordDecl(),
                                  LHS.Designator.Entries[PathLength]
                                      .getAsBaseOrMember().getPointer()));
      }

    //   -- Otherwise, S(E) is empty.
    } else {
      break;
    }
  }

  // Common case: no unions' lifetimes are started.
  if (UnionPathLengths.empty())
    return true;

  //   if modification of X [would access an inactive union member], an object
  //   of the type of X is implicitly created
  CompleteObject Obj =
      findCompleteObject(Info, LHSExpr, AK_Assign, LHS, LHSExpr->getType());
  if (!Obj)
    return false;
  for (std::pair<unsigned, const FieldDecl *> LengthAndField :
           llvm::reverse(UnionPathLengths)) {
    // Form a designator for the union object.
    SubobjectDesignator D = LHS.Designator;
    D.truncate(Info.Ctx, LHS.Base, LengthAndField.first);

    StartLifetimeOfUnionMemberHandler StartLifetime{LengthAndField.second};
    if (!findSubobject(Info, LHSExpr, Obj, D, StartLifetime))
      return false;
  }

  return true;
}

/// Determine if a class has any fields that might need to be copied by a
/// trivial copy or move operation.
static bool hasFields(const CXXRecordDecl *RD) {
  if (!RD || RD->isEmpty())
    return false;
  for (auto *FD : RD->fields()) {
    if (FD->isUnnamedBitfield())
      continue;
    return true;
  }
  for (auto &Base : RD->bases())
    if (hasFields(Base.getType()->getAsCXXRecordDecl()))
      return true;
  return false;
}

namespace {
typedef SmallVector<APValue, 8> ArgVector;
}

/// EvaluateArgs - Evaluate the arguments to a function call.
static bool EvaluateArgs(ArrayRef<const Expr *> Args, ArgVector &ArgValues,
                         EvalInfo &Info, const FunctionDecl *Callee) {
  bool Success = true;
  llvm::SmallBitVector ForbiddenNullArgs;
  if (Callee->hasAttr<NonNullAttr>()) {
    ForbiddenNullArgs.resize(Args.size());
    for (const auto *Attr : Callee->specific_attrs<NonNullAttr>()) {
      if (!Attr->args_size()) {
        ForbiddenNullArgs.set();
        break;
      } else
        for (auto Idx : Attr->args()) {
          unsigned ASTIdx = Idx.getASTIndex();
          if (ASTIdx >= Args.size())
            continue;
          ForbiddenNullArgs[ASTIdx] = 1;
        }
    }
  }
  for (unsigned Idx = 0; Idx < Args.size(); Idx++) {
    if (!Evaluate(ArgValues[Idx], Info, Args[Idx])) {
      // If we're checking for a potential constant expression, evaluate all
      // initializers even if some of them fail.
      if (!Info.noteFailure())
        return false;
      Success = false;
    } else if (!ForbiddenNullArgs.empty() &&
               ForbiddenNullArgs[Idx] &&
               ArgValues[Idx].isLValue() &&
               ArgValues[Idx].isNullPointer()) {
      Info.CCEDiag(Args[Idx], diag::note_non_null_attribute_failed);
      if (!Info.noteFailure())
        return false;
      Success = false;
    }
  }
  return Success;
}

/// Evaluate a function call.
static bool HandleFunctionCall(SourceLocation CallLoc,
                               const FunctionDecl *Callee, const LValue *This,
                               ArrayRef<const Expr*> Args, const Stmt *Body,
                               EvalInfo &Info, APValue &Result,
                               const LValue *ResultSlot) {
  ArgVector ArgValues(Args.size());
  if (!EvaluateArgs(Args, ArgValues, Info, Callee))
    return false;

  if (!Info.CheckCallLimit(CallLoc))
    return false;

  CallStackFrame Frame(Info, CallLoc, Callee, This, ArgValues.data());

  // For a trivial copy or move assignment, perform an APValue copy. This is
  // essential for unions, where the operations performed by the assignment
  // operator cannot be represented as statements.
  //
  // Skip this for non-union classes with no fields; in that case, the defaulted
  // copy/move does not actually read the object.
  const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(Callee);
  if (MD && MD->isDefaulted() &&
      (MD->getParent()->isUnion() ||
       (MD->isTrivial() && hasFields(MD->getParent())))) {
    assert(This &&
           (MD->isCopyAssignmentOperator() || MD->isMoveAssignmentOperator()));
    LValue RHS;
    RHS.setFrom(Info.Ctx, ArgValues[0]);
    APValue RHSValue;
    if (!handleLValueToRValueConversion(Info, Args[0], Args[0]->getType(), RHS,
                                        RHSValue, MD->getParent()->isUnion()))
      return false;
    if (Info.getLangOpts().CPlusPlus2a && MD->isTrivial() &&
        !HandleUnionActiveMemberChange(Info, Args[0], *This))
      return false;
    if (!handleAssignment(Info, Args[0], *This, MD->getThisType(),
                          RHSValue))
      return false;
    This->moveInto(Result);
    return true;
  } else if (MD && isLambdaCallOperator(MD)) {
    // We're in a lambda; determine the lambda capture field maps unless we're
    // just constexpr checking a lambda's call operator. constexpr checking is
    // done before the captures have been added to the closure object (unless
    // we're inferring constexpr-ness), so we don't have access to them in this
    // case. But since we don't need the captures to constexpr check, we can
    // just ignore them.
    if (!Info.checkingPotentialConstantExpression())
      MD->getParent()->getCaptureFields(Frame.LambdaCaptureFields,
                                        Frame.LambdaThisCaptureField);
  }

  StmtResult Ret = {Result, ResultSlot};
  EvalStmtResult ESR = EvaluateStmt(Ret, Info, Body);
  if (ESR == ESR_Succeeded) {
    if (Callee->getReturnType()->isVoidType())
      return true;
    Info.FFDiag(Callee->getEndLoc(), diag::note_constexpr_no_return);
  }
  return ESR == ESR_Returned;
}

/// Evaluate a constructor call.
static bool HandleConstructorCall(const Expr *E, const LValue &This,
                                  APValue *ArgValues,
                                  const CXXConstructorDecl *Definition,
                                  EvalInfo &Info, APValue &Result) {
  SourceLocation CallLoc = E->getExprLoc();
  if (!Info.CheckCallLimit(CallLoc))
    return false;

  const CXXRecordDecl *RD = Definition->getParent();
  if (RD->getNumVBases()) {
    Info.FFDiag(CallLoc, diag::note_constexpr_virtual_base) << RD;
    return false;
  }

  EvalInfo::EvaluatingConstructorRAII EvalObj(
      Info,
      ObjectUnderConstruction{This.getLValueBase(), This.Designator.Entries},
      RD->getNumBases());
  CallStackFrame Frame(Info, CallLoc, Definition, &This, ArgValues);

  // FIXME: Creating an APValue just to hold a nonexistent return value is
  // wasteful.
  APValue RetVal;
  StmtResult Ret = {RetVal, nullptr};

  // If it's a delegating constructor, delegate.
  if (Definition->isDelegatingConstructor()) {
    CXXConstructorDecl::init_const_iterator I = Definition->init_begin();
    {
      FullExpressionRAII InitScope(Info);
      if (!EvaluateInPlace(Result, Info, This, (*I)->getInit()) ||
          !InitScope.destroy())
        return false;
    }
    return EvaluateStmt(Ret, Info, Definition->getBody()) != ESR_Failed;
  }

  // For a trivial copy or move constructor, perform an APValue copy. This is
  // essential for unions (or classes with anonymous union members), where the
  // operations performed by the constructor cannot be represented by
  // ctor-initializers.
  //
  // Skip this for empty non-union classes; we should not perform an
  // lvalue-to-rvalue conversion on them because their copy constructor does not
  // actually read them.
  if (Definition->isDefaulted() && Definition->isCopyOrMoveConstructor() &&
      (Definition->getParent()->isUnion() ||
       (Definition->isTrivial() && hasFields(Definition->getParent())))) {
    LValue RHS;
    RHS.setFrom(Info.Ctx, ArgValues[0]);
    return handleLValueToRValueConversion(
        Info, E, Definition->getParamDecl(0)->getType().getNonReferenceType(),
        RHS, Result, Definition->getParent()->isUnion());
  }

  // Reserve space for the struct members.
  if (!RD->isUnion() && !Result.hasValue())
    Result = APValue(APValue::UninitStruct(), RD->getNumBases(),
                     std::distance(RD->field_begin(), RD->field_end()));

  if (RD->isInvalidDecl()) return false;
  const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);

  // A scope for temporaries lifetime-extended by reference members.
  BlockScopeRAII LifetimeExtendedScope(Info);

  bool Success = true;
  unsigned BasesSeen = 0;
#ifndef NDEBUG
  CXXRecordDecl::base_class_const_iterator BaseIt = RD->bases_begin();
#endif
  CXXRecordDecl::field_iterator FieldIt = RD->field_begin();
  auto SkipToField = [&](FieldDecl *FD, bool Indirect) {
    // We might be initializing the same field again if this is an indirect
    // field initialization.
    if (FieldIt == RD->field_end() ||
        FieldIt->getFieldIndex() > FD->getFieldIndex()) {
      assert(Indirect && "fields out of order?");
      return;
    }

    // Default-initialize any fields with no explicit initializer.
    for (; !declaresSameEntity(*FieldIt, FD); ++FieldIt) {
      assert(FieldIt != RD->field_end() && "missing field?");
      if (!FieldIt->isUnnamedBitfield())
        Result.getStructField(FieldIt->getFieldIndex()) =
            getDefaultInitValue(FieldIt->getType());
    }
    ++FieldIt;
  };
  for (const auto *I : Definition->inits()) {
    LValue Subobject = This;
    LValue SubobjectParent = This;
    APValue *Value = &Result;

    // Determine the subobject to initialize.
    FieldDecl *FD = nullptr;
    if (I->isBaseInitializer()) {
      QualType BaseType(I->getBaseClass(), 0);
#ifndef NDEBUG
      // Non-virtual base classes are initialized in the order in the class
      // definition. We have already checked for virtual base classes.
      assert(!BaseIt->isVirtual() && "virtual base for literal type");
      assert(Info.Ctx.hasSameType(BaseIt->getType(), BaseType) &&
             "base class initializers not in expected order");
      ++BaseIt;
#endif
      if (!HandleLValueDirectBase(Info, I->getInit(), Subobject, RD,
                                  BaseType->getAsCXXRecordDecl(), &Layout))
        return false;
      Value = &Result.getStructBase(BasesSeen++);
    } else if ((FD = I->getMember())) {
      if (!HandleLValueMember(Info, I->getInit(), Subobject, FD, &Layout))
        return false;
      if (RD->isUnion()) {
        Result = APValue(FD);
        Value = &Result.getUnionValue();
      } else {
        SkipToField(FD, false);
        Value = &Result.getStructField(FD->getFieldIndex());
      }
    } else if (IndirectFieldDecl *IFD = I->getIndirectMember()) {
      // Walk the indirect field decl's chain to find the object to initialize,
      // and make sure we've initialized every step along it.
      auto IndirectFieldChain = IFD->chain();
      for (auto *C : IndirectFieldChain) {
        FD = cast<FieldDecl>(C);
        CXXRecordDecl *CD = cast<CXXRecordDecl>(FD->getParent());
        // Switch the union field if it differs. This happens if we had
        // preceding zero-initialization, and we're now initializing a union
        // subobject other than the first.
        // FIXME: In this case, the values of the other subobjects are
        // specified, since zero-initialization sets all padding bits to zero.
        if (!Value->hasValue() ||
            (Value->isUnion() && Value->getUnionField() != FD)) {
          if (CD->isUnion())
            *Value = APValue(FD);
          else
            // FIXME: This immediately starts the lifetime of all members of an
            // anonymous struct. It would be preferable to strictly start member
            // lifetime in initialization order.
            *Value = getDefaultInitValue(Info.Ctx.getRecordType(CD));
        }
        // Store Subobject as its parent before updating it for the last element
        // in the chain.
        if (C == IndirectFieldChain.back())
          SubobjectParent = Subobject;
        if (!HandleLValueMember(Info, I->getInit(), Subobject, FD))
          return false;
        if (CD->isUnion())
          Value = &Value->getUnionValue();
        else {
          if (C == IndirectFieldChain.front() && !RD->isUnion())
            SkipToField(FD, true);
          Value = &Value->getStructField(FD->getFieldIndex());
        }
      }
    } else {
      llvm_unreachable("unknown base initializer kind");
    }

    // Need to override This for implicit field initializers as in this case
    // This refers to innermost anonymous struct/union containing initializer,
    // not to currently constructed class.
    const Expr *Init = I->getInit();
    ThisOverrideRAII ThisOverride(*Info.CurrentCall, &SubobjectParent,
                                  isa<CXXDefaultInitExpr>(Init));
    FullExpressionRAII InitScope(Info);
    if (!EvaluateInPlace(*Value, Info, Subobject, Init) ||
        (FD && FD->isBitField() &&
         !truncateBitfieldValue(Info, Init, *Value, FD))) {
      // If we're checking for a potential constant expression, evaluate all
      // initializers even if some of them fail.
      if (!Info.noteFailure())
        return false;
      Success = false;
    }

    // This is the point at which the dynamic type of the object becomes this
    // class type.
    if (I->isBaseInitializer() && BasesSeen == RD->getNumBases())
      EvalObj.finishedConstructingBases();
  }

  // Default-initialize any remaining fields.
  if (!RD->isUnion()) {
    for (; FieldIt != RD->field_end(); ++FieldIt) {
      if (!FieldIt->isUnnamedBitfield())
        Result.getStructField(FieldIt->getFieldIndex()) =
            getDefaultInitValue(FieldIt->getType());
    }
  }

  return Success &&
         EvaluateStmt(Ret, Info, Definition->getBody()) != ESR_Failed &&
         LifetimeExtendedScope.destroy();
}

static bool HandleConstructorCall(const Expr *E, const LValue &This,
                                  ArrayRef<const Expr*> Args,
                                  const CXXConstructorDecl *Definition,
                                  EvalInfo &Info, APValue &Result) {
  ArgVector ArgValues(Args.size());
  if (!EvaluateArgs(Args, ArgValues, Info, Definition))
    return false;

  return HandleConstructorCall(E, This, ArgValues.data(), Definition,
                               Info, Result);
}

static bool HandleDestructionImpl(EvalInfo &Info, SourceLocation CallLoc,
                                  const LValue &This, APValue &Value,
                                  QualType T) {
  // Objects can only be destroyed while they're within their lifetimes.
  // FIXME: We have no representation for whether an object of type nullptr_t
  // is in its lifetime; it usually doesn't matter. Perhaps we should model it
  // as indeterminate instead?
  if (Value.isAbsent() && !T->isNullPtrType()) {
    APValue Printable;
    This.moveInto(Printable);
    Info.FFDiag(CallLoc, diag::note_constexpr_destroy_out_of_lifetime)
      << Printable.getAsString(Info.Ctx, Info.Ctx.getLValueReferenceType(T));
    return false;
  }

  // Invent an expression for location purposes.
  // FIXME: We shouldn't need to do this.
  OpaqueValueExpr LocE(CallLoc, Info.Ctx.IntTy, VK_RValue);

  // For arrays, destroy elements right-to-left.
  if (const ConstantArrayType *CAT = Info.Ctx.getAsConstantArrayType(T)) {
    uint64_t Size = CAT->getSize().getZExtValue();
    QualType ElemT = CAT->getElementType();

    LValue ElemLV = This;
    ElemLV.addArray(Info, &LocE, CAT);
    if (!HandleLValueArrayAdjustment(Info, &LocE, ElemLV, ElemT, Size))
      return false;

    // Ensure that we have actual array elements available to destroy; the
    // destructors might mutate the value, so we can't run them on the array
    // filler.
    if (Size && Size > Value.getArrayInitializedElts())
      expandArray(Value, Value.getArraySize() - 1);

    for (; Size != 0; --Size) {
      APValue &Elem = Value.getArrayInitializedElt(Size - 1);
      if (!HandleLValueArrayAdjustment(Info, &LocE, ElemLV, ElemT, -1) ||
          !HandleDestructionImpl(Info, CallLoc, ElemLV, Elem, ElemT))
        return false;
    }

    // End the lifetime of this array now.
    Value = APValue();
    return true;
  }

  const CXXRecordDecl *RD = T->getAsCXXRecordDecl();
  if (!RD) {
    if (T.isDestructedType()) {
      Info.FFDiag(CallLoc, diag::note_constexpr_unsupported_destruction) << T;
      return false;
    }

    Value = APValue();
    return true;
  }

  if (RD->getNumVBases()) {
    Info.FFDiag(CallLoc, diag::note_constexpr_virtual_base) << RD;
    return false;
  }

  const CXXDestructorDecl *DD = RD->getDestructor();
  if (!DD && !RD->hasTrivialDestructor()) {
    Info.FFDiag(CallLoc);
    return false;
  }

  if (!DD || DD->isTrivial() ||
      (RD->isAnonymousStructOrUnion() && RD->isUnion())) {
    // A trivial destructor just ends the lifetime of the object. Check for
    // this case before checking for a body, because we might not bother
    // building a body for a trivial destructor. Note that it doesn't matter
    // whether the destructor is constexpr in this case; all trivial
    // destructors are constexpr.
    //
    // If an anonymous union would be destroyed, some enclosing destructor must
    // have been explicitly defined, and the anonymous union destruction should
    // have no effect.
    Value = APValue();
    return true;
  }

  if (!Info.CheckCallLimit(CallLoc))
    return false;

  const FunctionDecl *Definition = nullptr;
  const Stmt *Body = DD->getBody(Definition);

  if (!CheckConstexprFunction(Info, CallLoc, DD, Definition, Body))
    return false;

  CallStackFrame Frame(Info, CallLoc, Definition, &This, nullptr);

  // We're now in the period of destruction of this object.
  unsigned BasesLeft = RD->getNumBases();
  EvalInfo::EvaluatingDestructorRAII EvalObj(
      Info,
      ObjectUnderConstruction{This.getLValueBase(), This.Designator.Entries});
  if (!EvalObj.DidInsert) {
    // C++2a [class.dtor]p19:
    //   the behavior is undefined if the destructor is invoked for an object
    //   whose lifetime has ended
    // (Note that formally the lifetime ends when the period of destruction
    // begins, even though certain uses of the object remain valid until the
    // period of destruction ends.)
    Info.FFDiag(CallLoc, diag::note_constexpr_double_destroy);
    return false;
  }

  // FIXME: Creating an APValue just to hold a nonexistent return value is
  // wasteful.
  APValue RetVal;
  StmtResult Ret = {RetVal, nullptr};
  if (EvaluateStmt(Ret, Info, Definition->getBody()) == ESR_Failed)
    return false;

  // A union destructor does not implicitly destroy its members.
  if (RD->isUnion())
    return true;

  const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);

  // We don't have a good way to iterate fields in reverse, so collect all the
  // fields first and then walk them backwards.
  SmallVector<FieldDecl*, 16> Fields(RD->field_begin(), RD->field_end());
  for (const FieldDecl *FD : llvm::reverse(Fields)) {
    if (FD->isUnnamedBitfield())
      continue;

    LValue Subobject = This;
    if (!HandleLValueMember(Info, &LocE, Subobject, FD, &Layout))
      return false;

    APValue *SubobjectValue = &Value.getStructField(FD->getFieldIndex());
    if (!HandleDestructionImpl(Info, CallLoc, Subobject, *SubobjectValue,
                               FD->getType()))
      return false;
  }

  if (BasesLeft != 0)
    EvalObj.startedDestroyingBases();

  // Destroy base classes in reverse order.
  for (const CXXBaseSpecifier &Base : llvm::reverse(RD->bases())) {
    --BasesLeft;

    QualType BaseType = Base.getType();
    LValue Subobject = This;
    if (!HandleLValueDirectBase(Info, &LocE, Subobject, RD,
                                BaseType->getAsCXXRecordDecl(), &Layout))
      return false;

    APValue *SubobjectValue = &Value.getStructBase(BasesLeft);
    if (!HandleDestructionImpl(Info, CallLoc, Subobject, *SubobjectValue,
                               BaseType))
      return false;
  }
  assert(BasesLeft == 0 && "NumBases was wrong?");

  // The period of destruction ends now. The object is gone.
  Value = APValue();
  return true;
}

namespace {
struct DestroyObjectHandler {
  EvalInfo &Info;
  const Expr *E;
  const LValue &This;
  const AccessKinds AccessKind;

  typedef bool result_type;
  bool failed() { return false; }
  bool found(APValue &Subobj, QualType SubobjType) {
    return HandleDestructionImpl(Info, E->getExprLoc(), This, Subobj,
                                 SubobjType);
  }
  bool found(APSInt &Value, QualType SubobjType) {
    Info.FFDiag(E, diag::note_constexpr_destroy_complex_elem);
    return false;
  }
  bool found(APFloat &Value, QualType SubobjType) {
    Info.FFDiag(E, diag::note_constexpr_destroy_complex_elem);
    return false;
  }
};
}

/// Perform a destructor or pseudo-destructor call on the given object, which
/// might in general not be a complete object.
static bool HandleDestruction(EvalInfo &Info, const Expr *E,
                              const LValue &This, QualType ThisType) {
  CompleteObject Obj = findCompleteObject(Info, E, AK_Destroy, This, ThisType);
  DestroyObjectHandler Handler = {Info, E, This, AK_Destroy};
  return Obj && findSubobject(Info, E, Obj, This.Designator, Handler);
}

/// Destroy and end the lifetime of the given complete object.
static bool HandleDestruction(EvalInfo &Info, SourceLocation Loc,
                              APValue::LValueBase LVBase, APValue &Value,
                              QualType T) {
  // If we've had an unmodeled side-effect, we can't rely on mutable state
  // (such as the object we're about to destroy) being correct.
  if (Info.EvalStatus.HasSideEffects)
    return false;

  LValue LV;
  LV.set({LVBase});
  return HandleDestructionImpl(Info, Loc, LV, Value, T);
}

/// Perform a call to 'perator new' or to `__builtin_operator_new'.
static bool HandleOperatorNewCall(EvalInfo &Info, const CallExpr *E,
                                  LValue &Result) {
  if (Info.checkingPotentialConstantExpression() ||
      Info.SpeculativeEvaluationDepth)
    return false;

  // This is permitted only within a call to std::allocator<T>::allocate.
  auto Caller = Info.getStdAllocatorCaller("allocate");
  if (!Caller) {
    Info.FFDiag(E->getExprLoc(), Info.getLangOpts().CPlusPlus2a
                                     ? diag::note_constexpr_new_untyped
                                     : diag::note_constexpr_new);
    return false;
  }

  QualType ElemType = Caller.ElemType;
  if (ElemType->isIncompleteType() || ElemType->isFunctionType()) {
    Info.FFDiag(E->getExprLoc(),
                diag::note_constexpr_new_not_complete_object_type)
        << (ElemType->isIncompleteType() ? 0 : 1) << ElemType;
    return false;
  }

  APSInt ByteSize;
  if (!EvaluateInteger(E->getArg(0), ByteSize, Info))
    return false;
  bool IsNothrow = false;
  for (unsigned I = 1, N = E->getNumArgs(); I != N; ++I) {
    EvaluateIgnoredValue(Info, E->getArg(I));
    IsNothrow |= E->getType()->isNothrowT();
  }

  CharUnits ElemSize;
  if (!HandleSizeof(Info, E->getExprLoc(), ElemType, ElemSize))
    return false;
  APInt Size, Remainder;
  APInt ElemSizeAP(ByteSize.getBitWidth(), ElemSize.getQuantity());
  APInt::udivrem(ByteSize, ElemSizeAP, Size, Remainder);
  if (Remainder != 0) {
    // This likely indicates a bug in the implementation of 'std::allocator'.
    Info.FFDiag(E->getExprLoc(), diag::note_constexpr_operator_new_bad_size)
        << ByteSize << APSInt(ElemSizeAP, true) << ElemType;
    return false;
  }

  if (ByteSize.getActiveBits() > ConstantArrayType::getMaxSizeBits(Info.Ctx)) {
    if (IsNothrow) {
      Result.setNull(Info.Ctx, E->getType());
      return true;
    }

    Info.FFDiag(E, diag::note_constexpr_new_too_large) << APSInt(Size, true);
    return false;
  }

  QualType AllocType = Info.Ctx.getConstantArrayType(ElemType, Size, nullptr,
                                                     ArrayType::Normal, 0);
  APValue *Val = Info.createHeapAlloc(E, AllocType, Result);
  *Val = APValue(APValue::UninitArray(), 0, Size.getZExtValue());
  Result.addArray(Info, E, cast<ConstantArrayType>(AllocType));
  return true;
}

static bool hasVirtualDestructor(QualType T) {
  if (CXXRecordDecl *RD = T->getAsCXXRecordDecl())
    if (CXXDestructorDecl *DD = RD->getDestructor())
      return DD->isVirtual();
  return false;
}

static const FunctionDecl *getVirtualOperatorDelete(QualType T) {
  if (CXXRecordDecl *RD = T->getAsCXXRecordDecl())
    if (CXXDestructorDecl *DD = RD->getDestructor())
      return DD->isVirtual() ? DD->getOperatorDelete() : nullptr;
  return nullptr;
}

/// Check that the given object is a suitable pointer to a heap allocation that
/// still exists and is of the right kind for the purpose of a deletion.
///
/// On success, returns the heap allocation to deallocate. On failure, produces
/// a diagnostic and returns None.
static Optional<DynAlloc *> CheckDeleteKind(EvalInfo &Info, const Expr *E,
                                            const LValue &Pointer,
                                            DynAlloc::Kind DeallocKind) {
  auto PointerAsString = [&] {
    return Pointer.toString(Info.Ctx, Info.Ctx.VoidPtrTy);
  };

  DynamicAllocLValue DA = Pointer.Base.dyn_cast<DynamicAllocLValue>();
  if (!DA) {
    Info.FFDiag(E, diag::note_constexpr_delete_not_heap_alloc)
        << PointerAsString();
    if (Pointer.Base)
      NoteLValueLocation(Info, Pointer.Base);
    return None;
  }

  Optional<DynAlloc *> Alloc = Info.lookupDynamicAlloc(DA);
  if (!Alloc) {
    Info.FFDiag(E, diag::note_constexpr_double_delete);
    return None;
  }

  QualType AllocType = Pointer.Base.getDynamicAllocType();
  if (DeallocKind != (*Alloc)->getKind()) {
    Info.FFDiag(E, diag::note_constexpr_new_delete_mismatch)
        << DeallocKind << (*Alloc)->getKind() << AllocType;
    NoteLValueLocation(Info, Pointer.Base);
    return None;
  }

  bool Subobject = false;
  if (DeallocKind == DynAlloc::New) {
    Subobject = Pointer.Designator.MostDerivedPathLength != 0 ||
                Pointer.Designator.isOnePastTheEnd();
  } else {
    Subobject = Pointer.Designator.Entries.size() != 1 ||
                Pointer.Designator.Entries[0].getAsArrayIndex() != 0;
  }
  if (Subobject) {
    Info.FFDiag(E, diag::note_constexpr_delete_subobject)
        << PointerAsString() << Pointer.Designator.isOnePastTheEnd();
    return None;
  }

  return Alloc;
}

// Perform a call to 'operator delete' or '__builtin_operator_delete'.
bool HandleOperatorDeleteCall(EvalInfo &Info, const CallExpr *E) {
  if (Info.checkingPotentialConstantExpression() ||
      Info.SpeculativeEvaluationDepth)
    return false;

  // This is permitted only within a call to std::allocator<T>::deallocate.
  if (!Info.getStdAllocatorCaller("deallocate")) {
    Info.FFDiag(E->getExprLoc());
    return true;
  }

  LValue Pointer;
  if (!EvaluatePointer(E->getArg(0), Pointer, Info))
    return false;
  for (unsigned I = 1, N = E->getNumArgs(); I != N; ++I)
    EvaluateIgnoredValue(Info, E->getArg(I));

  if (Pointer.Designator.Invalid)
    return false;

  // Deleting a null pointer has no effect.
  if (Pointer.isNullPointer())
    return true;

  if (!CheckDeleteKind(Info, E, Pointer, DynAlloc::StdAllocator))
    return false;

  Info.HeapAllocs.erase(Pointer.Base.get<DynamicAllocLValue>());
  return true;
}

//===----------------------------------------------------------------------===//
// Generic Evaluation
//===----------------------------------------------------------------------===//
namespace {

class BitCastBuffer {
  // FIXME: We're going to need bit-level granularity when we support
  // bit-fields.
  // FIXME: Its possible under the C++ standard for 'char' to not be 8 bits, but
  // we don't support a host or target where that is the case. Still, we should
  // use a more generic type in case we ever do.
  SmallVector<Optional<unsigned char>, 32> Bytes;

  static_assert(std::numeric_limits<unsigned char>::digits >= 8,
                "Need at least 8 bit unsigned char");

  bool TargetIsLittleEndian;

public:
  BitCastBuffer(CharUnits Width, bool TargetIsLittleEndian)
      : Bytes(Width.getQuantity()),
        TargetIsLittleEndian(TargetIsLittleEndian) {}

  LLVM_NODISCARD
  bool readObject(CharUnits Offset, CharUnits Width,
                  SmallVectorImpl<unsigned char> &Output) const {
    for (CharUnits I = Offset, E = Offset + Width; I != E; ++I) {
      // If a byte of an integer is uninitialized, then the whole integer is
      // uninitalized.
      if (!Bytes[I.getQuantity()])
        return false;
      Output.push_back(*Bytes[I.getQuantity()]);
    }
    if (llvm::sys::IsLittleEndianHost != TargetIsLittleEndian)
      std::reverse(Output.begin(), Output.end());
    return true;
  }

  void writeObject(CharUnits Offset, SmallVectorImpl<unsigned char> &Input) {
    if (llvm::sys::IsLittleEndianHost != TargetIsLittleEndian)
      std::reverse(Input.begin(), Input.end());

    size_t Index = 0;
    for (unsigned char Byte : Input) {
      assert(!Bytes[Offset.getQuantity() + Index] && "overwriting a byte?");
      Bytes[Offset.getQuantity() + Index] = Byte;
      ++Index;
    }
  }

  size_t size() { return Bytes.size(); }
};

/// Traverse an APValue to produce an BitCastBuffer, emulating how the current
/// target would represent the value at runtime.
class APValueToBufferConverter {
  EvalInfo &Info;
  BitCastBuffer Buffer;
  const CastExpr *BCE;

  APValueToBufferConverter(EvalInfo &Info, CharUnits ObjectWidth,
                           const CastExpr *BCE)
      : Info(Info),
        Buffer(ObjectWidth, Info.Ctx.getTargetInfo().isLittleEndian()),
        BCE(BCE) {}

  bool visit(const APValue &Val, QualType Ty) {
    return visit(Val, Ty, CharUnits::fromQuantity(0));
  }

  // Write out Val with type Ty into Buffer starting at Offset.
  bool visit(const APValue &Val, QualType Ty, CharUnits Offset) {
    assert((size_t)Offset.getQuantity() <= Buffer.size());

    // As a special case, nullptr_t has an indeterminate value.
    if (Ty->isNullPtrType())
      return true;

    // Dig through Src to find the byte at SrcOffset.
    switch (Val.getKind()) {
    case APValue::Indeterminate:
    case APValue::None:
      return true;

    case APValue::Int:
      return visitInt(Val.getInt(), Ty, Offset);
    case APValue::Float:
      return visitFloat(Val.getFloat(), Ty, Offset);
    case APValue::Array:
      return visitArray(Val, Ty, Offset);
    case APValue::Struct:
      return visitRecord(Val, Ty, Offset);

    case APValue::ComplexInt:
    case APValue::ComplexFloat:
    case APValue::Vector:
    case APValue::FixedPoint:
      // FIXME: We should support these.

    case APValue::Union:
    case APValue::MemberPointer:
    case APValue::AddrLabelDiff: {
      Info.FFDiag(BCE->getBeginLoc(),
                  diag::note_constexpr_bit_cast_unsupported_type)
          << Ty;
      return false;
    }

    case APValue::LValue:
      llvm_unreachable("LValue subobject in bit_cast?");
    }
    llvm_unreachable("Unhandled APValue::ValueKind");
  }

  bool visitRecord(const APValue &Val, QualType Ty, CharUnits Offset) {
    const RecordDecl *RD = Ty->getAsRecordDecl();
    const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);

    // Visit the base classes.
    if (auto *CXXRD = dyn_cast<CXXRecordDecl>(RD)) {
      for (size_t I = 0, E = CXXRD->getNumBases(); I != E; ++I) {
        const CXXBaseSpecifier &BS = CXXRD->bases_begin()[I];
        CXXRecordDecl *BaseDecl = BS.getType()->getAsCXXRecordDecl();

        if (!visitRecord(Val.getStructBase(I), BS.getType(),
                         Layout.getBaseClassOffset(BaseDecl) + Offset))
          return false;
      }
    }

    // Visit the fields.
    unsigned FieldIdx = 0;
    for (FieldDecl *FD : RD->fields()) {
      if (FD->isBitField()) {
        Info.FFDiag(BCE->getBeginLoc(),
                    diag::note_constexpr_bit_cast_unsupported_bitfield);
        return false;
      }

      uint64_t FieldOffsetBits = Layout.getFieldOffset(FieldIdx);

      assert(FieldOffsetBits % Info.Ctx.getCharWidth() == 0 &&
             "only bit-fields can have sub-char alignment");
      CharUnits FieldOffset =
          Info.Ctx.toCharUnitsFromBits(FieldOffsetBits) + Offset;
      QualType FieldTy = FD->getType();
      if (!visit(Val.getStructField(FieldIdx), FieldTy, FieldOffset))
        return false;
      ++FieldIdx;
    }

    return true;
  }

  bool visitArray(const APValue &Val, QualType Ty, CharUnits Offset) {
    const auto *CAT =
        dyn_cast_or_null<ConstantArrayType>(Ty->getAsArrayTypeUnsafe());
    if (!CAT)
      return false;

    CharUnits ElemWidth = Info.Ctx.getTypeSizeInChars(CAT->getElementType());
    unsigned NumInitializedElts = Val.getArrayInitializedElts();
    unsigned ArraySize = Val.getArraySize();
    // First, initialize the initialized elements.
    for (unsigned I = 0; I != NumInitializedElts; ++I) {
      const APValue &SubObj = Val.getArrayInitializedElt(I);
      if (!visit(SubObj, CAT->getElementType(), Offset + I * ElemWidth))
        return false;
    }

    // Next, initialize the rest of the array using the filler.
    if (Val.hasArrayFiller()) {
      const APValue &Filler = Val.getArrayFiller();
      for (unsigned I = NumInitializedElts; I != ArraySize; ++I) {
        if (!visit(Filler, CAT->getElementType(), Offset + I * ElemWidth))
          return false;
      }
    }

    return true;
  }

  bool visitInt(const APSInt &Val, QualType Ty, CharUnits Offset) {
    CharUnits Width = Info.Ctx.getTypeSizeInChars(Ty);
    SmallVector<unsigned char, 8> Bytes(Width.getQuantity());
    llvm::StoreIntToMemory(Val, &*Bytes.begin(), Width.getQuantity());
    Buffer.writeObject(Offset, Bytes);
    return true;
  }

  bool visitFloat(const APFloat &Val, QualType Ty, CharUnits Offset) {
    APSInt AsInt(Val.bitcastToAPInt());
    return visitInt(AsInt, Ty, Offset);
  }

public:
  static Optional<BitCastBuffer> convert(EvalInfo &Info, const APValue &Src,
                                         const CastExpr *BCE) {
    CharUnits DstSize = Info.Ctx.getTypeSizeInChars(BCE->getType());
    APValueToBufferConverter Converter(Info, DstSize, BCE);
    if (!Converter.visit(Src, BCE->getSubExpr()->getType()))
      return None;
    return Converter.Buffer;
  }
};

/// Write an BitCastBuffer into an APValue.
class BufferToAPValueConverter {
  EvalInfo &Info;
  const BitCastBuffer &Buffer;
  const CastExpr *BCE;

  BufferToAPValueConverter(EvalInfo &Info, const BitCastBuffer &Buffer,
                           const CastExpr *BCE)
      : Info(Info), Buffer(Buffer), BCE(BCE) {}

  // Emit an unsupported bit_cast type error. Sema refuses to build a bit_cast
  // with an invalid type, so anything left is a deficiency on our part (FIXME).
  // Ideally this will be unreachable.
  llvm::NoneType unsupportedType(QualType Ty) {
    Info.FFDiag(BCE->getBeginLoc(),
                diag::note_constexpr_bit_cast_unsupported_type)
        << Ty;
    return None;
  }

  Optional<APValue> visit(const BuiltinType *T, CharUnits Offset,
                          const EnumType *EnumSugar = nullptr) {
    if (T->isNullPtrType()) {
      uint64_t NullValue = Info.Ctx.getTargetNullPointerValue(QualType(T, 0));
      return APValue((Expr *)nullptr,
                     /*Offset=*/CharUnits::fromQuantity(NullValue),
                     APValue::NoLValuePath{}, /*IsNullPtr=*/true);
    }

    CharUnits SizeOf = Info.Ctx.getTypeSizeInChars(T);
    SmallVector<uint8_t, 8> Bytes;
    if (!Buffer.readObject(Offset, SizeOf, Bytes)) {
      // If this is std::byte or unsigned char, then its okay to store an
      // indeterminate value.
      bool IsStdByte = EnumSugar && EnumSugar->isStdByteType();
      bool IsUChar =
          !EnumSugar && (T->isSpecificBuiltinType(BuiltinType::UChar) ||
                         T->isSpecificBuiltinType(BuiltinType::Char_U));
      if (!IsStdByte && !IsUChar) {
        QualType DisplayType(EnumSugar ? (const Type *)EnumSugar : T, 0);
        Info.FFDiag(BCE->getExprLoc(),
                    diag::note_constexpr_bit_cast_indet_dest)
            << DisplayType << Info.Ctx.getLangOpts().CharIsSigned;
        return None;
      }

      return APValue::IndeterminateValue();
    }

    APSInt Val(SizeOf.getQuantity() * Info.Ctx.getCharWidth(), true);
    llvm::LoadIntFromMemory(Val, &*Bytes.begin(), Bytes.size());

    if (T->isIntegralOrEnumerationType()) {
      Val.setIsSigned(T->isSignedIntegerOrEnumerationType());
      return APValue(Val);
    }

    if (T->isRealFloatingType()) {
      const llvm::fltSemantics &Semantics =
          Info.Ctx.getFloatTypeSemantics(QualType(T, 0));
      return APValue(APFloat(Semantics, Val));
    }

    return unsupportedType(QualType(T, 0));
  }

  Optional<APValue> visit(const RecordType *RTy, CharUnits Offset) {
    const RecordDecl *RD = RTy->getAsRecordDecl();
    const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);

    unsigned NumBases = 0;
    if (auto *CXXRD = dyn_cast<CXXRecordDecl>(RD))
      NumBases = CXXRD->getNumBases();

    APValue ResultVal(APValue::UninitStruct(), NumBases,
                      std::distance(RD->field_begin(), RD->field_end()));

    // Visit the base classes.
    if (auto *CXXRD = dyn_cast<CXXRecordDecl>(RD)) {
      for (size_t I = 0, E = CXXRD->getNumBases(); I != E; ++I) {
        const CXXBaseSpecifier &BS = CXXRD->bases_begin()[I];
        CXXRecordDecl *BaseDecl = BS.getType()->getAsCXXRecordDecl();
        if (BaseDecl->isEmpty() ||
            Info.Ctx.getASTRecordLayout(BaseDecl).getNonVirtualSize().isZero())
          continue;

        Optional<APValue> SubObj = visitType(
            BS.getType(), Layout.getBaseClassOffset(BaseDecl) + Offset);
        if (!SubObj)
          return None;
        ResultVal.getStructBase(I) = *SubObj;
      }
    }

    // Visit the fields.
    unsigned FieldIdx = 0;
    for (FieldDecl *FD : RD->fields()) {
      // FIXME: We don't currently support bit-fields. A lot of the logic for
      // this is in CodeGen, so we need to factor it around.
      if (FD->isBitField()) {
        Info.FFDiag(BCE->getBeginLoc(),
                    diag::note_constexpr_bit_cast_unsupported_bitfield);
        return None;
      }

      uint64_t FieldOffsetBits = Layout.getFieldOffset(FieldIdx);
      assert(FieldOffsetBits % Info.Ctx.getCharWidth() == 0);

      CharUnits FieldOffset =
          CharUnits::fromQuantity(FieldOffsetBits / Info.Ctx.getCharWidth()) +
          Offset;
      QualType FieldTy = FD->getType();
      Optional<APValue> SubObj = visitType(FieldTy, FieldOffset);
      if (!SubObj)
        return None;
      ResultVal.getStructField(FieldIdx) = *SubObj;
      ++FieldIdx;
    }

    return ResultVal;
  }

  Optional<APValue> visit(const EnumType *Ty, CharUnits Offset) {
    QualType RepresentationType = Ty->getDecl()->getIntegerType();
    assert(!RepresentationType.isNull() &&
           "enum forward decl should be caught by Sema");
    const auto *AsBuiltin =
        RepresentationType.getCanonicalType()->castAs<BuiltinType>();
    // Recurse into the underlying type. Treat std::byte transparently as
    // unsigned char.
    return visit(AsBuiltin, Offset, /*EnumTy=*/Ty);
  }

  Optional<APValue> visit(const ConstantArrayType *Ty, CharUnits Offset) {
    size_t Size = Ty->getSize().getLimitedValue();
    CharUnits ElementWidth = Info.Ctx.getTypeSizeInChars(Ty->getElementType());

    APValue ArrayValue(APValue::UninitArray(), Size, Size);
    for (size_t I = 0; I != Size; ++I) {
      Optional<APValue> ElementValue =
          visitType(Ty->getElementType(), Offset + I * ElementWidth);
      if (!ElementValue)
        return None;
      ArrayValue.getArrayInitializedElt(I) = std::move(*ElementValue);
    }

    return ArrayValue;
  }

  Optional<APValue> visit(const Type *Ty, CharUnits Offset) {
    return unsupportedType(QualType(Ty, 0));
  }

  Optional<APValue> visitType(QualType Ty, CharUnits Offset) {
    QualType Can = Ty.getCanonicalType();

    switch (Can->getTypeClass()) {
#define TYPE(Class, Base)                                                      \
  case Type::Class:                                                            \
    return visit(cast<Class##Type>(Can.getTypePtr()), Offset);
#define ABSTRACT_TYPE(Class, Base)
#define NON_CANONICAL_TYPE(Class, Base)                                        \
  case Type::Class:                                                            \
    llvm_unreachable("non-canonical type should be impossible!");
#define DEPENDENT_TYPE(Class, Base)                                            \
  case Type::Class:                                                            \
    llvm_unreachable(                                                          \
        "dependent types aren't supported in the constant evaluator!");
#define NON_CANONICAL_UNLESS_DEPENDENT(Class, Base)                            \
  case Type::Class:                                                            \
    llvm_unreachable("either dependent or not canonical!");
#include "clang/AST/TypeNodes.inc"
    }
    llvm_unreachable("Unhandled Type::TypeClass");
  }

public:
  // Pull out a full value of type DstType.
  static Optional<APValue> convert(EvalInfo &Info, BitCastBuffer &Buffer,
                                   const CastExpr *BCE) {
    BufferToAPValueConverter Converter(Info, Buffer, BCE);
    return Converter.visitType(BCE->getType(), CharUnits::fromQuantity(0));
  }
};

static bool checkBitCastConstexprEligibilityType(SourceLocation Loc,
                                                 QualType Ty, EvalInfo *Info,
                                                 const ASTContext &Ctx,
                                                 bool CheckingDest) {
  Ty = Ty.getCanonicalType();

  auto diag = [&](int Reason) {
    if (Info)
      Info->FFDiag(Loc, diag::note_constexpr_bit_cast_invalid_type)
          << CheckingDest << (Reason == 4) << Reason;
    return false;
  };
  auto note = [&](int Construct, QualType NoteTy, SourceLocation NoteLoc) {
    if (Info)
      Info->Note(NoteLoc, diag::note_constexpr_bit_cast_invalid_subtype)
          << NoteTy << Construct << Ty;
    return false;
  };

  if (Ty->isUnionType())
    return diag(0);
  if (Ty->isPointerType())
    return diag(1);
  if (Ty->isMemberPointerType())
    return diag(2);
  if (Ty.isVolatileQualified())
    return diag(3);

  if (RecordDecl *Record = Ty->getAsRecordDecl()) {
    if (auto *CXXRD = dyn_cast<CXXRecordDecl>(Record)) {
      for (CXXBaseSpecifier &BS : CXXRD->bases())
        if (!checkBitCastConstexprEligibilityType(Loc, BS.getType(), Info, Ctx,
                                                  CheckingDest))
          return note(1, BS.getType(), BS.getBeginLoc());
    }
    for (FieldDecl *FD : Record->fields()) {
      if (FD->getType()->isReferenceType())
        return diag(4);
      if (!checkBitCastConstexprEligibilityType(Loc, FD->getType(), Info, Ctx,
                                                CheckingDest))
        return note(0, FD->getType(), FD->getBeginLoc());
    }
  }

  if (Ty->isArrayType() &&
      !checkBitCastConstexprEligibilityType(Loc, Ctx.getBaseElementType(Ty),
                                            Info, Ctx, CheckingDest))
    return false;

  return true;
}

static bool checkBitCastConstexprEligibility(EvalInfo *Info,
                                             const ASTContext &Ctx,
                                             const CastExpr *BCE) {
  bool DestOK = checkBitCastConstexprEligibilityType(
      BCE->getBeginLoc(), BCE->getType(), Info, Ctx, true);
  bool SourceOK = DestOK && checkBitCastConstexprEligibilityType(
                                BCE->getBeginLoc(),
                                BCE->getSubExpr()->getType(), Info, Ctx, false);
  return SourceOK;
}

static bool handleLValueToRValueBitCast(EvalInfo &Info, APValue &DestValue,
                                        APValue &SourceValue,
                                        const CastExpr *BCE) {
  assert(CHAR_BIT == 8 && Info.Ctx.getTargetInfo().getCharWidth() == 8 &&
         "no host or target supports non 8-bit chars");
  assert(SourceValue.isLValue() &&
         "LValueToRValueBitcast requires an lvalue operand!");

  if (!checkBitCastConstexprEligibility(&Info, Info.Ctx, BCE))
    return false;

  LValue SourceLValue;
  APValue SourceRValue;
  SourceLValue.setFrom(Info.Ctx, SourceValue);
  if (!handleLValueToRValueConversion(
          Info, BCE, BCE->getSubExpr()->getType().withConst(), SourceLValue,
          SourceRValue, /*WantObjectRepresentation=*/true))
    return false;

  // Read out SourceValue into a char buffer.
  Optional<BitCastBuffer> Buffer =
      APValueToBufferConverter::convert(Info, SourceRValue, BCE);
  if (!Buffer)
    return false;

  // Write out the buffer into a new APValue.
  Optional<APValue> MaybeDestValue =
      BufferToAPValueConverter::convert(Info, *Buffer, BCE);
  if (!MaybeDestValue)
    return false;

  DestValue = std::move(*MaybeDestValue);
  return true;
}

template <class Derived>
class ExprEvaluatorBase
  : public ConstStmtVisitor<Derived, bool> {
private:
  Derived &getDerived() { return static_cast<Derived&>(*this); }
  bool DerivedSuccess(const APValue &V, const Expr *E) {
    return getDerived().Success(V, E);
  }
  bool DerivedZeroInitialization(const Expr *E) {
    return getDerived().ZeroInitialization(E);
  }

  // Check whether a conditional operator with a non-constant condition is a
  // potential constant expression. If neither arm is a potential constant
  // expression, then the conditional operator is not either.
  template<typename ConditionalOperator>
  void CheckPotentialConstantConditional(const ConditionalOperator *E) {
    assert(Info.checkingPotentialConstantExpression());

    // Speculatively evaluate both arms.
    SmallVector<PartialDiagnosticAt, 8> Diag;
    {
      SpeculativeEvaluationRAII Speculate(Info, &Diag);
      StmtVisitorTy::Visit(E->getFalseExpr());
      if (Diag.empty())
        return;
    }

    {
      SpeculativeEvaluationRAII Speculate(Info, &Diag);
      Diag.clear();
      StmtVisitorTy::Visit(E->getTrueExpr());
      if (Diag.empty())
        return;
    }

    Error(E, diag::note_constexpr_conditional_never_const);
  }


  template<typename ConditionalOperator>
  bool HandleConditionalOperator(const ConditionalOperator *E) {
    bool BoolResult;
    if (!EvaluateAsBooleanCondition(E->getCond(), BoolResult, Info)) {
      if (Info.checkingPotentialConstantExpression() && Info.noteFailure()) {
        CheckPotentialConstantConditional(E);
        return false;
      }
      if (Info.noteFailure()) {
        StmtVisitorTy::Visit(E->getTrueExpr());
        StmtVisitorTy::Visit(E->getFalseExpr());
      }
      return false;
    }

    Expr *EvalExpr = BoolResult ? E->getTrueExpr() : E->getFalseExpr();
    return StmtVisitorTy::Visit(EvalExpr);
  }

protected:
  EvalInfo &Info;
  typedef ConstStmtVisitor<Derived, bool> StmtVisitorTy;
  typedef ExprEvaluatorBase ExprEvaluatorBaseTy;

  OptionalDiagnostic CCEDiag(const Expr *E, diag::kind D) {
    return Info.CCEDiag(E, D);
  }

  bool ZeroInitialization(const Expr *E) { return Error(E); }

public:
  ExprEvaluatorBase(EvalInfo &Info) : Info(Info) {}

  EvalInfo &getEvalInfo() { return Info; }

  /// Report an evaluation error. This should only be called when an error is
  /// first discovered. When propagating an error, just return false.
  bool Error(const Expr *E, diag::kind D) {
    Info.FFDiag(E, D);
    return false;
  }
  bool Error(const Expr *E) {
    return Error(E, diag::note_invalid_subexpr_in_const_expr);
  }

  bool VisitStmt(const Stmt *) {
    llvm_unreachable("Expression evaluator should not be called on stmts");
  }
  bool VisitExpr(const Expr *E) {
    return Error(E);
  }

  bool VisitConstantExpr(const ConstantExpr *E)
    { return StmtVisitorTy::Visit(E->getSubExpr()); }
  bool VisitParenExpr(const ParenExpr *E)
    { return StmtVisitorTy::Visit(E->getSubExpr()); }
  bool VisitUnaryExtension(const UnaryOperator *E)
    { return StmtVisitorTy::Visit(E->getSubExpr()); }
  bool VisitUnaryPlus(const UnaryOperator *E)
    { return StmtVisitorTy::Visit(E->getSubExpr()); }
  bool VisitChooseExpr(const ChooseExpr *E)
    { return StmtVisitorTy::Visit(E->getChosenSubExpr()); }
  bool VisitGenericSelectionExpr(const GenericSelectionExpr *E)
    { return StmtVisitorTy::Visit(E->getResultExpr()); }
  bool VisitSubstNonTypeTemplateParmExpr(const SubstNonTypeTemplateParmExpr *E)
    { return StmtVisitorTy::Visit(E->getReplacement()); }
  bool VisitCXXDefaultArgExpr(const CXXDefaultArgExpr *E) {
    TempVersionRAII RAII(*Info.CurrentCall);
    SourceLocExprScopeGuard Guard(E, Info.CurrentCall->CurSourceLocExprScope);
    return StmtVisitorTy::Visit(E->getExpr());
  }
  bool VisitCXXDefaultInitExpr(const CXXDefaultInitExpr *E) {
    TempVersionRAII RAII(*Info.CurrentCall);
    // The initializer may not have been parsed yet, or might be erroneous.
    if (!E->getExpr())
      return Error(E);
    SourceLocExprScopeGuard Guard(E, Info.CurrentCall->CurSourceLocExprScope);
    return StmtVisitorTy::Visit(E->getExpr());
  }

  bool VisitExprWithCleanups(const ExprWithCleanups *E) {
    FullExpressionRAII Scope(Info);
    return StmtVisitorTy::Visit(E->getSubExpr()) && Scope.destroy();
  }

  // Temporaries are registered when created, so we don't care about
  // CXXBindTemporaryExpr.
  bool VisitCXXBindTemporaryExpr(const CXXBindTemporaryExpr *E) {
    return StmtVisitorTy::Visit(E->getSubExpr());
  }

  bool VisitCXXReinterpretCastExpr(const CXXReinterpretCastExpr *E) {
    CCEDiag(E, diag::note_constexpr_invalid_cast) << 0;
    return static_cast<Derived*>(this)->VisitCastExpr(E);
  }
  bool VisitCXXDynamicCastExpr(const CXXDynamicCastExpr *E) {
    if (!Info.Ctx.getLangOpts().CPlusPlus2a)
      CCEDiag(E, diag::note_constexpr_invalid_cast) << 1;
    return static_cast<Derived*>(this)->VisitCastExpr(E);
  }
  bool VisitBuiltinBitCastExpr(const BuiltinBitCastExpr *E) {
    return static_cast<Derived*>(this)->VisitCastExpr(E);
  }

  bool VisitBinaryOperator(const BinaryOperator *E) {
    switch (E->getOpcode()) {
    default:
      return Error(E);

    case BO_Comma:
      VisitIgnoredValue(E->getLHS());
      return StmtVisitorTy::Visit(E->getRHS());

    case BO_PtrMemD:
    case BO_PtrMemI: {
      LValue Obj;
      if (!HandleMemberPointerAccess(Info, E, Obj))
        return false;
      APValue Result;
      if (!handleLValueToRValueConversion(Info, E, E->getType(), Obj, Result))
        return false;
      return DerivedSuccess(Result, E);
    }
    }
  }

  bool VisitCXXRewrittenBinaryOperator(const CXXRewrittenBinaryOperator *E) {
    return StmtVisitorTy::Visit(E->getSemanticForm());
  }

  bool VisitBinaryConditionalOperator(const BinaryConditionalOperator *E) {
    // Evaluate and cache the common expression. We treat it as a temporary,
    // even though it's not quite the same thing.
    LValue CommonLV;
    if (!Evaluate(Info.CurrentCall->createTemporary(
                      E->getOpaqueValue(),
                      getStorageType(Info.Ctx, E->getOpaqueValue()), false,
                      CommonLV),
                  Info, E->getCommon()))
      return false;

    return HandleConditionalOperator(E);
  }

  bool VisitConditionalOperator(const ConditionalOperator *E) {
    bool IsBcpCall = false;
    // If the condition (ignoring parens) is a __builtin_constant_p call,
    // the result is a constant expression if it can be folded without
    // side-effects. This is an important GNU extension. See GCC PR38377
    // for discussion.
    if (const CallExpr *CallCE =
          dyn_cast<CallExpr>(E->getCond()->IgnoreParenCasts()))
      if (CallCE->getBuiltinCallee() == Builtin::BI__builtin_constant_p)
        IsBcpCall = true;

    // Always assume __builtin_constant_p(...) ? ... : ... is a potential
    // constant expression; we can't check whether it's potentially foldable.
    // FIXME: We should instead treat __builtin_constant_p as non-constant if
    // it would return 'false' in this mode.
    if (Info.checkingPotentialConstantExpression() && IsBcpCall)
      return false;

    FoldConstant Fold(Info, IsBcpCall);
    if (!HandleConditionalOperator(E)) {
      Fold.keepDiagnostics();
      return false;
    }

    return true;
  }

  bool VisitOpaqueValueExpr(const OpaqueValueExpr *E) {
    if (APValue *Value = Info.CurrentCall->getCurrentTemporary(E))
      return DerivedSuccess(*Value, E);

    const Expr *Source = E->getSourceExpr();
    if (!Source)
      return Error(E);
    if (Source == E) { // sanity checking.
      assert(0 && "OpaqueValueExpr recursively refers to itself");
      return Error(E);
    }
    return StmtVisitorTy::Visit(Source);
  }

  bool VisitPseudoObjectExpr(const PseudoObjectExpr *E) {
    for (const Expr *SemE : E->semantics()) {
      if (auto *OVE = dyn_cast<OpaqueValueExpr>(SemE)) {
        // FIXME: We can't handle the case where an OpaqueValueExpr is also the
        // result expression: there could be two different LValues that would
        // refer to the same object in that case, and we can't model that.
        if (SemE == E->getResultExpr())
          return Error(E);

        // Unique OVEs get evaluated if and when we encounter them when
        // emitting the rest of the semantic form, rather than eagerly.
        if (OVE->isUnique())
          continue;

        LValue LV;
        if (!Evaluate(Info.CurrentCall->createTemporary(
                          OVE, getStorageType(Info.Ctx, OVE), false, LV),
                      Info, OVE->getSourceExpr()))
          return false;
      } else if (SemE == E->getResultExpr()) {
        if (!StmtVisitorTy::Visit(SemE))
          return false;
      } else {
        if (!EvaluateIgnoredValue(Info, SemE))
          return false;
      }
    }
    return true;
  }

  bool VisitCallExpr(const CallExpr *E) {
    APValue Result;
    if (!handleCallExpr(E, Result, nullptr))
      return false;
    return DerivedSuccess(Result, E);
  }

  bool handleCallExpr(const CallExpr *E, APValue &Result,
                     const LValue *ResultSlot) {
    const Expr *Callee = E->getCallee()->IgnoreParens();
    QualType CalleeType = Callee->getType();

    const FunctionDecl *FD = nullptr;
    LValue *This = nullptr, ThisVal;
    auto Args = llvm::makeArrayRef(E->getArgs(), E->getNumArgs());
    bool HasQualifier = false;

    // Extract function decl and 'this' pointer from the callee.
    if (CalleeType->isSpecificBuiltinType(BuiltinType::BoundMember)) {
      const CXXMethodDecl *Member = nullptr;
      if (const MemberExpr *ME = dyn_cast<MemberExpr>(Callee)) {
        // Explicit bound member calls, such as x.f() or p->g();
        if (!EvaluateObjectArgument(Info, ME->getBase(), ThisVal))
          return false;
        Member = dyn_cast<CXXMethodDecl>(ME->getMemberDecl());
        if (!Member)
          return Error(Callee);
        This = &ThisVal;
        HasQualifier = ME->hasQualifier();
      } else if (const BinaryOperator *BE = dyn_cast<BinaryOperator>(Callee)) {
        // Indirect bound member calls ('.*' or '->*').
        const ValueDecl *D =
            HandleMemberPointerAccess(Info, BE, ThisVal, false);
        if (!D)
          return false;
        Member = dyn_cast<CXXMethodDecl>(D);
        if (!Member)
          return Error(Callee);
        This = &ThisVal;
      } else if (const auto *PDE = dyn_cast<CXXPseudoDestructorExpr>(Callee)) {
        if (!Info.getLangOpts().CPlusPlus2a)
          Info.CCEDiag(PDE, diag::note_constexpr_pseudo_destructor);
        // FIXME: If pseudo-destructor calls ever start ending the lifetime of
        // their callee, we should start calling HandleDestruction here.
        // For now, we just evaluate the object argument and discard it.
        return EvaluateObjectArgument(Info, PDE->getBase(), ThisVal);
      } else
        return Error(Callee);
      FD = Member;
    } else if (CalleeType->isFunctionPointerType()) {
      LValue Call;
      if (!EvaluatePointer(Callee, Call, Info))
        return false;

      if (!Call.getLValueOffset().isZero())
        return Error(Callee);
      FD = dyn_cast_or_null<FunctionDecl>(
                             Call.getLValueBase().dyn_cast<const ValueDecl*>());
      if (!FD)
        return Error(Callee);
      // Don't call function pointers which have been cast to some other type.
      // Per DR (no number yet), the caller and callee can differ in noexcept.
      if (!Info.Ctx.hasSameFunctionTypeIgnoringExceptionSpec(
        CalleeType->getPointeeType(), FD->getType())) {
        return Error(E);
      }

      // Overloaded operator calls to member functions are represented as normal
      // calls with '*this' as the first argument.
      const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(FD);
      if (MD && !MD->isStatic()) {
        // FIXME: When selecting an implicit conversion for an overloaded
        // operator delete, we sometimes try to evaluate calls to conversion
        // operators without a 'this' parameter!
        if (Args.empty())
          return Error(E);

        if (!EvaluateObjectArgument(Info, Args[0], ThisVal))
          return false;
        This = &ThisVal;
        Args = Args.slice(1);
      } else if (MD && MD->isLambdaStaticInvoker()) {
        // Map the static invoker for the lambda back to the call operator.
        // Conveniently, we don't have to slice out the 'this' argument (as is
        // being done for the non-static case), since a static member function
        // doesn't have an implicit argument passed in.
        const CXXRecordDecl *ClosureClass = MD->getParent();
        assert(
            ClosureClass->captures_begin() == ClosureClass->captures_end() &&
            "Number of captures must be zero for conversion to function-ptr");

        const CXXMethodDecl *LambdaCallOp =
            ClosureClass->getLambdaCallOperator();

        // Set 'FD', the function that will be called below, to the call
        // operator.  If the closure object represents a generic lambda, find
        // the corresponding specialization of the call operator.

        if (ClosureClass->isGenericLambda()) {
          assert(MD->isFunctionTemplateSpecialization() &&
                 "A generic lambda's static-invoker function must be a "
                 "template specialization");
          const TemplateArgumentList *TAL = MD->getTemplateSpecializationArgs();
          FunctionTemplateDecl *CallOpTemplate =
              LambdaCallOp->getDescribedFunctionTemplate();
          void *InsertPos = nullptr;
          FunctionDecl *CorrespondingCallOpSpecialization =
              CallOpTemplate->findSpecialization(TAL->asArray(), InsertPos);
          assert(CorrespondingCallOpSpecialization &&
                 "We must always have a function call operator specialization "
                 "that corresponds to our static invoker specialization");
          FD = cast<CXXMethodDecl>(CorrespondingCallOpSpecialization);
        } else
          FD = LambdaCallOp;
      } else if (FD->isReplaceableGlobalAllocationFunction()) {
        if (FD->getDeclName().getCXXOverloadedOperator() == OO_New ||
            FD->getDeclName().getCXXOverloadedOperator() == OO_Array_New) {
          LValue Ptr;
          if (!HandleOperatorNewCall(Info, E, Ptr))
            return false;
          Ptr.moveInto(Result);
          return true;
        } else {
          return HandleOperatorDeleteCall(Info, E);
        }
      }
    } else
      return Error(E);

    SmallVector<QualType, 4> CovariantAdjustmentPath;
    if (This) {
      auto *NamedMember = dyn_cast<CXXMethodDecl>(FD);
      if (NamedMember && NamedMember->isVirtual() && !HasQualifier) {
        // Perform virtual dispatch, if necessary.
        FD = HandleVirtualDispatch(Info, E, *This, NamedMember,
                                   CovariantAdjustmentPath);
        if (!FD)
          return false;
      } else {
        // Check that the 'this' pointer points to an object of the right type.
        // FIXME: If this is an assignment operator call, we may need to change
        // the active union member before we check this.
        if (!checkNonVirtualMemberCallThisPointer(Info, E, *This, NamedMember))
          return false;
      }
    }

    // Destructor calls are different enough that they have their own codepath.
    if (auto *DD = dyn_cast<CXXDestructorDecl>(FD)) {
      assert(This && "no 'this' pointer for destructor call");
      return HandleDestruction(Info, E, *This,
                               Info.Ctx.getRecordType(DD->getParent()));
    }

    const FunctionDecl *Definition = nullptr;
    Stmt *Body = FD->getBody(Definition);

    if (!CheckConstexprFunction(Info, E->getExprLoc(), FD, Definition, Body) ||
        !HandleFunctionCall(E->getExprLoc(), Definition, This, Args, Body, Info,
                            Result, ResultSlot))
      return false;

    if (!CovariantAdjustmentPath.empty() &&
        !HandleCovariantReturnAdjustment(Info, E, Result,
                                         CovariantAdjustmentPath))
      return false;

    return true;
  }

  bool VisitCompoundLiteralExpr(const CompoundLiteralExpr *E) {
    return StmtVisitorTy::Visit(E->getInitializer());
  }
  bool VisitInitListExpr(const InitListExpr *E) {
    if (E->getNumInits() == 0)
      return DerivedZeroInitialization(E);
    if (E->getNumInits() == 1)
      return StmtVisitorTy::Visit(E->getInit(0));
    return Error(E);
  }
  bool VisitImplicitValueInitExpr(const ImplicitValueInitExpr *E) {
    return DerivedZeroInitialization(E);
  }
  bool VisitCXXScalarValueInitExpr(const CXXScalarValueInitExpr *E) {
    return DerivedZeroInitialization(E);
  }
  bool VisitCXXNullPtrLiteralExpr(const CXXNullPtrLiteralExpr *E) {
    return DerivedZeroInitialization(E);
  }

  /// A member expression where the object is a prvalue is itself a prvalue.
  bool VisitMemberExpr(const MemberExpr *E) {
    assert(!Info.Ctx.getLangOpts().CPlusPlus11 &&
           "missing temporary materialization conversion");
    assert(!E->isArrow() && "missing call to bound member function?");

    APValue Val;
    if (!Evaluate(Val, Info, E->getBase()))
      return false;

    QualType BaseTy = E->getBase()->getType();

    const FieldDecl *FD = dyn_cast<FieldDecl>(E->getMemberDecl());
    if (!FD) return Error(E);
    assert(!FD->getType()->isReferenceType() && "prvalue reference?");
    assert(BaseTy->castAs<RecordType>()->getDecl()->getCanonicalDecl() ==
           FD->getParent()->getCanonicalDecl() && "record / field mismatch");

    // Note: there is no lvalue base here. But this case should only ever
    // happen in C or in C++98, where we cannot be evaluating a constexpr
    // constructor, which is the only case the base matters.
    CompleteObject Obj(APValue::LValueBase(), &Val, BaseTy);
    SubobjectDesignator Designator(BaseTy);
    Designator.addDeclUnchecked(FD);

    APValue Result;
    return extractSubobject(Info, E, Obj, Designator, Result) &&
           DerivedSuccess(Result, E);
  }

  bool VisitExtVectorElementExpr(const ExtVectorElementExpr *E) {
    APValue Val;
    if (!Evaluate(Val, Info, E->getBase()))
      return false;

    if (Val.isVector()) {
      SmallVector<uint32_t, 4> Indices;
      E->getEncodedElementAccess(Indices);
      if (Indices.size() == 1) {
        // Return scalar.
        return DerivedSuccess(Val.getVectorElt(Indices[0]), E);
      } else {
        // Construct new APValue vector.
        SmallVector<APValue, 4> Elts;
        for (unsigned I = 0; I < Indices.size(); ++I) {
          Elts.push_back(Val.getVectorElt(Indices[I]));
        }
        APValue VecResult(Elts.data(), Indices.size());
        return DerivedSuccess(VecResult, E);
      }
    }

    return false;
  }

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      break;

    case CK_AtomicToNonAtomic: {
      APValue AtomicVal;
      // This does not need to be done in place even for class/array types:
      // atomic-to-non-atomic conversion implies copying the object
      // representation.
      if (!Evaluate(AtomicVal, Info, E->getSubExpr()))
        return false;
      return DerivedSuccess(AtomicVal, E);
    }

    case CK_NoOp:
    case CK_UserDefinedConversion:
      return StmtVisitorTy::Visit(E->getSubExpr());

    case CK_LValueToRValue: {
      LValue LVal;
      if (!EvaluateLValue(E->getSubExpr(), LVal, Info))
        return false;
      APValue RVal;
      // Note, we use the subexpression's type in order to retain cv-qualifiers.
      if (!handleLValueToRValueConversion(Info, E, E->getSubExpr()->getType(),
                                          LVal, RVal))
        return false;
      return DerivedSuccess(RVal, E);
    }
    case CK_LValueToRValueBitCast: {
      APValue DestValue, SourceValue;
      if (!Evaluate(SourceValue, Info, E->getSubExpr()))
        return false;
      if (!handleLValueToRValueBitCast(Info, DestValue, SourceValue, E))
        return false;
      return DerivedSuccess(DestValue, E);
    }

    case CK_AddressSpaceConversion: {
      APValue Value;
      if (!Evaluate(Value, Info, E->getSubExpr()))
        return false;
      return DerivedSuccess(Value, E);
    }
    }

    return Error(E);
  }

  bool VisitUnaryPostInc(const UnaryOperator *UO) {
    return VisitUnaryPostIncDec(UO);
  }
  bool VisitUnaryPostDec(const UnaryOperator *UO) {
    return VisitUnaryPostIncDec(UO);
  }
  bool VisitUnaryPostIncDec(const UnaryOperator *UO) {
    if (!Info.getLangOpts().CPlusPlus14 && !Info.keepEvaluatingAfterFailure())
      return Error(UO);

    LValue LVal;
    if (!EvaluateLValue(UO->getSubExpr(), LVal, Info))
      return false;
    APValue RVal;
    if (!handleIncDec(this->Info, UO, LVal, UO->getSubExpr()->getType(),
                      UO->isIncrementOp(), &RVal))
      return false;
    return DerivedSuccess(RVal, UO);
  }

  bool VisitStmtExpr(const StmtExpr *E) {
    // We will have checked the full-expressions inside the statement expression
    // when they were completed, and don't need to check them again now.
    if (Info.checkingForUndefinedBehavior())
      return Error(E);

    const CompoundStmt *CS = E->getSubStmt();
    if (CS->body_empty())
      return true;

    BlockScopeRAII Scope(Info);
    for (CompoundStmt::const_body_iterator BI = CS->body_begin(),
                                           BE = CS->body_end();
         /**/; ++BI) {
      if (BI + 1 == BE) {
        const Expr *FinalExpr = dyn_cast<Expr>(*BI);
        if (!FinalExpr) {
          Info.FFDiag((*BI)->getBeginLoc(),
                      diag::note_constexpr_stmt_expr_unsupported);
          return false;
        }
        return this->Visit(FinalExpr) && Scope.destroy();
      }

      APValue ReturnValue;
      StmtResult Result = { ReturnValue, nullptr };
      EvalStmtResult ESR = EvaluateStmt(Result, Info, *BI);
      if (ESR != ESR_Succeeded) {
        // FIXME: If the statement-expression terminated due to 'return',
        // 'break', or 'continue', it would be nice to propagate that to
        // the outer statement evaluation rather than bailing out.
        if (ESR != ESR_Failed)
          Info.FFDiag((*BI)->getBeginLoc(),
                      diag::note_constexpr_stmt_expr_unsupported);
        return false;
      }
    }

    llvm_unreachable("Return from function from the loop above.");
  }

  /// Visit a value which is evaluated, but whose value is ignored.
  void VisitIgnoredValue(const Expr *E) {
    EvaluateIgnoredValue(Info, E);
  }

  /// Potentially visit a MemberExpr's base expression.
  void VisitIgnoredBaseExpression(const Expr *E) {
    // While MSVC doesn't evaluate the base expression, it does diagnose the
    // presence of side-effecting behavior.
    if (Info.getLangOpts().MSVCCompat && !E->HasSideEffects(Info.Ctx))
      return;
    VisitIgnoredValue(E);
  }
};

} // namespace

//===----------------------------------------------------------------------===//
// Common base class for lvalue and temporary evaluation.
//===----------------------------------------------------------------------===//
namespace {
template<class Derived>
class LValueExprEvaluatorBase
  : public ExprEvaluatorBase<Derived> {
protected:
  LValue &Result;
  bool InvalidBaseOK;
  typedef LValueExprEvaluatorBase LValueExprEvaluatorBaseTy;
  typedef ExprEvaluatorBase<Derived> ExprEvaluatorBaseTy;

  bool Success(APValue::LValueBase B) {
    Result.set(B);
    return true;
  }

  bool evaluatePointer(const Expr *E, LValue &Result) {
    return EvaluatePointer(E, Result, this->Info, InvalidBaseOK);
  }

public:
  LValueExprEvaluatorBase(EvalInfo &Info, LValue &Result, bool InvalidBaseOK)
      : ExprEvaluatorBaseTy(Info), Result(Result),
        InvalidBaseOK(InvalidBaseOK) {}

  bool Success(const APValue &V, const Expr *E) {
    Result.setFrom(this->Info.Ctx, V);
    return true;
  }

  bool VisitMemberExpr(const MemberExpr *E) {
    // Handle non-static data members.
    QualType BaseTy;
    bool EvalOK;
    if (E->isArrow()) {
      EvalOK = evaluatePointer(E->getBase(), Result);
      BaseTy = E->getBase()->getType()->castAs<PointerType>()->getPointeeType();
    } else if (E->getBase()->isRValue()) {
      assert(E->getBase()->getType()->isRecordType());
      EvalOK = EvaluateTemporary(E->getBase(), Result, this->Info);
      BaseTy = E->getBase()->getType();
    } else {
      EvalOK = this->Visit(E->getBase());
      BaseTy = E->getBase()->getType();
    }
    if (!EvalOK) {
      if (!InvalidBaseOK)
        return false;
      Result.setInvalid(E);
      return true;
    }

    const ValueDecl *MD = E->getMemberDecl();
    if (const FieldDecl *FD = dyn_cast<FieldDecl>(E->getMemberDecl())) {
      assert(BaseTy->castAs<RecordType>()->getDecl()->getCanonicalDecl() ==
             FD->getParent()->getCanonicalDecl() && "record / field mismatch");
      (void)BaseTy;
      if (!HandleLValueMember(this->Info, E, Result, FD))
        return false;
    } else if (const IndirectFieldDecl *IFD = dyn_cast<IndirectFieldDecl>(MD)) {
      if (!HandleLValueIndirectMember(this->Info, E, Result, IFD))
        return false;
    } else
      return this->Error(E);

    if (MD->getType()->isReferenceType()) {
      APValue RefValue;
      if (!handleLValueToRValueConversion(this->Info, E, MD->getType(), Result,
                                          RefValue))
        return false;
      return Success(RefValue, E);
    }
    return true;
  }

  bool VisitBinaryOperator(const BinaryOperator *E) {
    switch (E->getOpcode()) {
    default:
      return ExprEvaluatorBaseTy::VisitBinaryOperator(E);

    case BO_PtrMemD:
    case BO_PtrMemI:
      return HandleMemberPointerAccess(this->Info, E, Result);
    }
  }

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      return ExprEvaluatorBaseTy::VisitCastExpr(E);

    case CK_DerivedToBase:
    case CK_UncheckedDerivedToBase:
      if (!this->Visit(E->getSubExpr()))
        return false;

      // Now figure out the necessary offset to add to the base LV to get from
      // the derived class to the base class.
      return HandleLValueBasePath(this->Info, E, E->getSubExpr()->getType(),
                                  Result);
    }
  }
};
}

//===----------------------------------------------------------------------===//
// LValue Evaluation
//
// This is used for evaluating lvalues (in C and C++), xvalues (in C++11),
// function designators (in C), decl references to void objects (in C), and
// temporaries (if building with -Wno-address-of-temporary).
//
// LValue evaluation produces values comprising a base expression of one of the
// following types:
// - Declarations
//  * VarDecl
//  * FunctionDecl
// - Literals
//  * CompoundLiteralExpr in C (and in global scope in C++)
//  * StringLiteral
//  * PredefinedExpr
//  * ObjCStringLiteralExpr
//  * ObjCEncodeExpr
//  * AddrLabelExpr
//  * BlockExpr
//  * CallExpr for a MakeStringConstant builtin
// - typeid(T) expressions, as TypeInfoLValues
// - Locals and temporaries
//  * MaterializeTemporaryExpr
//  * Any Expr, with a CallIndex indicating the function in which the temporary
//    was evaluated, for cases where the MaterializeTemporaryExpr is missing
//    from the AST (FIXME).
//  * A MaterializeTemporaryExpr that has static storage duration, with no
//    CallIndex, for a lifetime-extended temporary.
// plus an offset in bytes.
//===----------------------------------------------------------------------===//
namespace {
class LValueExprEvaluator
  : public LValueExprEvaluatorBase<LValueExprEvaluator> {
public:
  LValueExprEvaluator(EvalInfo &Info, LValue &Result, bool InvalidBaseOK) :
    LValueExprEvaluatorBaseTy(Info, Result, InvalidBaseOK) {}

  bool VisitVarDecl(const Expr *E, const VarDecl *VD);
  bool VisitUnaryPreIncDec(const UnaryOperator *UO);

  bool VisitDeclRefExpr(const DeclRefExpr *E);
  bool VisitPredefinedExpr(const PredefinedExpr *E) { return Success(E); }
  bool VisitMaterializeTemporaryExpr(const MaterializeTemporaryExpr *E);
  bool VisitCompoundLiteralExpr(const CompoundLiteralExpr *E);
  bool VisitMemberExpr(const MemberExpr *E);
  bool VisitStringLiteral(const StringLiteral *E) { return Success(E); }
  bool VisitObjCEncodeExpr(const ObjCEncodeExpr *E) { return Success(E); }
  bool VisitCXXTypeidExpr(const CXXTypeidExpr *E);
  bool VisitCXXUuidofExpr(const CXXUuidofExpr *E);
  bool VisitArraySubscriptExpr(const ArraySubscriptExpr *E);
  bool VisitUnaryDeref(const UnaryOperator *E);
  bool VisitUnaryReal(const UnaryOperator *E);
  bool VisitUnaryImag(const UnaryOperator *E);
  bool VisitUnaryPreInc(const UnaryOperator *UO) {
    return VisitUnaryPreIncDec(UO);
  }
  bool VisitUnaryPreDec(const UnaryOperator *UO) {
    return VisitUnaryPreIncDec(UO);
  }
  bool VisitBinAssign(const BinaryOperator *BO);
  bool VisitCompoundAssignOperator(const CompoundAssignOperator *CAO);

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      return LValueExprEvaluatorBaseTy::VisitCastExpr(E);

    case CK_LValueBitCast:
      this->CCEDiag(E, diag::note_constexpr_invalid_cast) << 2;
      if (!Visit(E->getSubExpr()))
        return false;
      Result.Designator.setInvalid();
      return true;

    case CK_BaseToDerived:
      if (!Visit(E->getSubExpr()))
        return false;
      return HandleBaseToDerivedCast(Info, E, Result);

    case CK_Dynamic:
      if (!Visit(E->getSubExpr()))
        return false;
      return HandleDynamicCast(Info, cast<ExplicitCastExpr>(E), Result);
    }
  }
};
} // end anonymous namespace

/// Evaluate an expression as an lvalue. This can be legitimately called on
/// expressions which are not glvalues, in three cases:
///  * function designators in C, and
///  * "extern void" objects
///  * @selector() expressions in Objective-C
static bool EvaluateLValue(const Expr *E, LValue &Result, EvalInfo &Info,
                           bool InvalidBaseOK) {
  assert(E->isGLValue() || E->getType()->isFunctionType() ||
         E->getType()->isVoidType() || isa<ObjCSelectorExpr>(E));
  return LValueExprEvaluator(Info, Result, InvalidBaseOK).Visit(E);
}

bool LValueExprEvaluator::VisitDeclRefExpr(const DeclRefExpr *E) {
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(E->getDecl()))
    return Success(FD);
  if (const VarDecl *VD = dyn_cast<VarDecl>(E->getDecl()))
    return VisitVarDecl(E, VD);
  if (const BindingDecl *BD = dyn_cast<BindingDecl>(E->getDecl()))
    return Visit(BD->getBinding());
  return Error(E);
}


bool LValueExprEvaluator::VisitVarDecl(const Expr *E, const VarDecl *VD) {

  // If we are within a lambda's call operator, check whether the 'VD' referred
  // to within 'E' actually represents a lambda-capture that maps to a
  // data-member/field within the closure object, and if so, evaluate to the
  // field or what the field refers to.
  if (Info.CurrentCall && isLambdaCallOperator(Info.CurrentCall->Callee) &&
      isa<DeclRefExpr>(E) &&
      cast<DeclRefExpr>(E)->refersToEnclosingVariableOrCapture()) {
    // We don't always have a complete capture-map when checking or inferring if
    // the function call operator meets the requirements of a constexpr function
    // - but we don't need to evaluate the captures to determine constexprness
    // (dcl.constexpr C++17).
    if (Info.checkingPotentialConstantExpression())
      return false;

    if (auto *FD = Info.CurrentCall->LambdaCaptureFields.lookup(VD)) {
      // Start with 'Result' referring to the complete closure object...
      Result = *Info.CurrentCall->This;
      // ... then update it to refer to the field of the closure object
      // that represents the capture.
      if (!HandleLValueMember(Info, E, Result, FD))
        return false;
      // And if the field is of reference type, update 'Result' to refer to what
      // the field refers to.
      if (FD->getType()->isReferenceType()) {
        APValue RVal;
        if (!handleLValueToRValueConversion(Info, E, FD->getType(), Result,
                                            RVal))
          return false;
        Result.setFrom(Info.Ctx, RVal);
      }
      return true;
    }
  }
  CallStackFrame *Frame = nullptr;
  if (VD->hasLocalStorage() && Info.CurrentCall->Index > 1) {
    // Only if a local variable was declared in the function currently being
    // evaluated, do we expect to be able to find its value in the current
    // frame. (Otherwise it was likely declared in an enclosing context and
    // could either have a valid evaluatable value (for e.g. a constexpr
    // variable) or be ill-formed (and trigger an appropriate evaluation
    // diagnostic)).
    if (Info.CurrentCall->Callee &&
        Info.CurrentCall->Callee->Equals(VD->getDeclContext())) {
      Frame = Info.CurrentCall;
    }
  }

  if (!VD->getType()->isReferenceType()) {
    if (Frame) {
      Result.set({VD, Frame->Index,
                  Info.CurrentCall->getCurrentTemporaryVersion(VD)});
      return true;
    }
    return Success(VD);
  }

  APValue *V;
  if (!evaluateVarDeclInit(Info, E, VD, Frame, V, nullptr))
    return false;
  if (!V->hasValue()) {
    // FIXME: Is it possible for V to be indeterminate here? If so, we should
    // adjust the diagnostic to say that.
    if (!Info.checkingPotentialConstantExpression())
      Info.FFDiag(E, diag::note_constexpr_use_uninit_reference);
    return false;
  }
  return Success(*V, E);
}

bool LValueExprEvaluator::VisitMaterializeTemporaryExpr(
    const MaterializeTemporaryExpr *E) {
  // Walk through the expression to find the materialized temporary itself.
  SmallVector<const Expr *, 2> CommaLHSs;
  SmallVector<SubobjectAdjustment, 2> Adjustments;
  const Expr *Inner =
      E->getSubExpr()->skipRValueSubobjectAdjustments(CommaLHSs, Adjustments);

  // If we passed any comma operators, evaluate their LHSs.
  for (unsigned I = 0, N = CommaLHSs.size(); I != N; ++I)
    if (!EvaluateIgnoredValue(Info, CommaLHSs[I]))
      return false;

  // A materialized temporary with static storage duration can appear within the
  // result of a constant expression evaluation, so we need to preserve its
  // value for use outside this evaluation.
  APValue *Value;
  if (E->getStorageDuration() == SD_Static) {
    Value = E->getOrCreateValue(true);
    *Value = APValue();
    Result.set(E);
  } else {
    Value = &Info.CurrentCall->createTemporary(
        E, E->getType(), E->getStorageDuration() == SD_Automatic, Result);
  }

  QualType Type = Inner->getType();

  // Materialize the temporary itself.
  if (!EvaluateInPlace(*Value, Info, Result, Inner)) {
    *Value = APValue();
    return false;
  }

  // Adjust our lvalue to refer to the desired subobject.
  for (unsigned I = Adjustments.size(); I != 0; /**/) {
    --I;
    switch (Adjustments[I].Kind) {
    case SubobjectAdjustment::DerivedToBaseAdjustment:
      if (!HandleLValueBasePath(Info, Adjustments[I].DerivedToBase.BasePath,
                                Type, Result))
        return false;
      Type = Adjustments[I].DerivedToBase.BasePath->getType();
      break;

    case SubobjectAdjustment::FieldAdjustment:
      if (!HandleLValueMember(Info, E, Result, Adjustments[I].Field))
        return false;
      Type = Adjustments[I].Field->getType();
      break;

    case SubobjectAdjustment::MemberPointerAdjustment:
      if (!HandleMemberPointerAccess(this->Info, Type, Result,
                                     Adjustments[I].Ptr.RHS))
        return false;
      Type = Adjustments[I].Ptr.MPT->getPointeeType();
      break;
    }
  }

  return true;
}

bool
LValueExprEvaluator::VisitCompoundLiteralExpr(const CompoundLiteralExpr *E) {
  assert((!Info.getLangOpts().CPlusPlus || E->isFileScope()) &&
         "lvalue compound literal in c++?");
  // Defer visiting the literal until the lvalue-to-rvalue conversion. We can
  // only see this when folding in C, so there's no standard to follow here.
  return Success(E);
}

bool LValueExprEvaluator::VisitCXXTypeidExpr(const CXXTypeidExpr *E) {
  TypeInfoLValue TypeInfo;

  if (!E->isPotentiallyEvaluated()) {
    if (E->isTypeOperand())
      TypeInfo = TypeInfoLValue(E->getTypeOperand(Info.Ctx).getTypePtr());
    else
      TypeInfo = TypeInfoLValue(E->getExprOperand()->getType().getTypePtr());
  } else {
    if (!Info.Ctx.getLangOpts().CPlusPlus2a) {
      Info.CCEDiag(E, diag::note_constexpr_typeid_polymorphic)
        << E->getExprOperand()->getType()
        << E->getExprOperand()->getSourceRange();
    }

    if (!Visit(E->getExprOperand()))
      return false;

    Optional<DynamicType> DynType =
        ComputeDynamicType(Info, E, Result, AK_TypeId);
    if (!DynType)
      return false;

    TypeInfo =
        TypeInfoLValue(Info.Ctx.getRecordType(DynType->Type).getTypePtr());
  }

  return Success(APValue::LValueBase::getTypeInfo(TypeInfo, E->getType()));
}

bool LValueExprEvaluator::VisitCXXUuidofExpr(const CXXUuidofExpr *E) {
  return Success(E);
}

bool LValueExprEvaluator::VisitMemberExpr(const MemberExpr *E) {
  // Handle static data members.
  if (const VarDecl *VD = dyn_cast<VarDecl>(E->getMemberDecl())) {
    VisitIgnoredBaseExpression(E->getBase());
    return VisitVarDecl(E, VD);
  }

  // Handle static member functions.
  if (const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(E->getMemberDecl())) {
    if (MD->isStatic()) {
      VisitIgnoredBaseExpression(E->getBase());
      return Success(MD);
    }
  }

  // Handle non-static data members.
  return LValueExprEvaluatorBaseTy::VisitMemberExpr(E);
}

bool LValueExprEvaluator::VisitArraySubscriptExpr(const ArraySubscriptExpr *E) {
  // FIXME: Deal with vectors as array subscript bases.
  if (E->getBase()->getType()->isVectorType())
    return Error(E);

  bool Success = true;
  if (!evaluatePointer(E->getBase(), Result)) {
    if (!Info.noteFailure())
      return false;
    Success = false;
  }

  APSInt Index;
  if (!EvaluateInteger(E->getIdx(), Index, Info))
    return false;

  return Success &&
         HandleLValueArrayAdjustment(Info, E, Result, E->getType(), Index);
}

bool LValueExprEvaluator::VisitUnaryDeref(const UnaryOperator *E) {
  return evaluatePointer(E->getSubExpr(), Result);
}

bool LValueExprEvaluator::VisitUnaryReal(const UnaryOperator *E) {
  if (!Visit(E->getSubExpr()))
    return false;
  // __real is a no-op on scalar lvalues.
  if (E->getSubExpr()->getType()->isAnyComplexType())
    HandleLValueComplexElement(Info, E, Result, E->getType(), false);
  return true;
}

bool LValueExprEvaluator::VisitUnaryImag(const UnaryOperator *E) {
  assert(E->getSubExpr()->getType()->isAnyComplexType() &&
         "lvalue __imag__ on scalar?");
  if (!Visit(E->getSubExpr()))
    return false;
  HandleLValueComplexElement(Info, E, Result, E->getType(), true);
  return true;
}

bool LValueExprEvaluator::VisitUnaryPreIncDec(const UnaryOperator *UO) {
  if (!Info.getLangOpts().CPlusPlus14 && !Info.keepEvaluatingAfterFailure())
    return Error(UO);

  if (!this->Visit(UO->getSubExpr()))
    return false;

  return handleIncDec(
      this->Info, UO, Result, UO->getSubExpr()->getType(),
      UO->isIncrementOp(), nullptr);
}

bool LValueExprEvaluator::VisitCompoundAssignOperator(
    const CompoundAssignOperator *CAO) {
  if (!Info.getLangOpts().CPlusPlus14 && !Info.keepEvaluatingAfterFailure())
    return Error(CAO);

  APValue RHS;

  // The overall lvalue result is the result of evaluating the LHS.
  if (!this->Visit(CAO->getLHS())) {
    if (Info.noteFailure())
      Evaluate(RHS, this->Info, CAO->getRHS());
    return false;
  }

  if (!Evaluate(RHS, this->Info, CAO->getRHS()))
    return false;

  return handleCompoundAssignment(
      this->Info, CAO,
      Result, CAO->getLHS()->getType(), CAO->getComputationLHSType(),
      CAO->getOpForCompoundAssignment(CAO->getOpcode()), RHS);
}

bool LValueExprEvaluator::VisitBinAssign(const BinaryOperator *E) {
  if (!Info.getLangOpts().CPlusPlus14 && !Info.keepEvaluatingAfterFailure())
    return Error(E);

  APValue NewVal;

  if (!this->Visit(E->getLHS())) {
    if (Info.noteFailure())
      Evaluate(NewVal, this->Info, E->getRHS());
    return false;
  }

  if (!Evaluate(NewVal, this->Info, E->getRHS()))
    return false;

  if (Info.getLangOpts().CPlusPlus2a &&
      !HandleUnionActiveMemberChange(Info, E->getLHS(), Result))
    return false;

  return handleAssignment(this->Info, E, Result, E->getLHS()->getType(),
                          NewVal);
}

//===----------------------------------------------------------------------===//
// Pointer Evaluation
//===----------------------------------------------------------------------===//

/// Attempts to compute the number of bytes available at the pointer
/// returned by a function with the alloc_size attribute. Returns true if we
/// were successful. Places an unsigned number into `Result`.
///
/// This expects the given CallExpr to be a call to a function with an
/// alloc_size attribute.
static bool getBytesReturnedByAllocSizeCall(const ASTContext &Ctx,
                                            const CallExpr *Call,
                                            llvm::APInt &Result) {
  const AllocSizeAttr *AllocSize = getAllocSizeAttr(Call);

  assert(AllocSize && AllocSize->getElemSizeParam().isValid());
  unsigned SizeArgNo = AllocSize->getElemSizeParam().getASTIndex();
  unsigned BitsInSizeT = Ctx.getTypeSize(Ctx.getSizeType());
  if (Call->getNumArgs() <= SizeArgNo)
    return false;

  auto EvaluateAsSizeT = [&](const Expr *E, APSInt &Into) {
    Expr::EvalResult ExprResult;
    if (!E->EvaluateAsInt(ExprResult, Ctx, Expr::SE_AllowSideEffects))
      return false;
    Into = ExprResult.Val.getInt();
    if (Into.isNegative() || !Into.isIntN(BitsInSizeT))
      return false;
    Into = Into.zextOrSelf(BitsInSizeT);
    return true;
  };

  APSInt SizeOfElem;
  if (!EvaluateAsSizeT(Call->getArg(SizeArgNo), SizeOfElem))
    return false;

  if (!AllocSize->getNumElemsParam().isValid()) {
    Result = std::move(SizeOfElem);
    return true;
  }

  APSInt NumberOfElems;
  unsigned NumArgNo = AllocSize->getNumElemsParam().getASTIndex();
  if (!EvaluateAsSizeT(Call->getArg(NumArgNo), NumberOfElems))
    return false;

  bool Overflow;
  llvm::APInt BytesAvailable = SizeOfElem.umul_ov(NumberOfElems, Overflow);
  if (Overflow)
    return false;

  Result = std::move(BytesAvailable);
  return true;
}

/// Convenience function. LVal's base must be a call to an alloc_size
/// function.
static bool getBytesReturnedByAllocSizeCall(const ASTContext &Ctx,
                                            const LValue &LVal,
                                            llvm::APInt &Result) {
  assert(isBaseAnAllocSizeCall(LVal.getLValueBase()) &&
         "Can't get the size of a non alloc_size function");
  const auto *Base = LVal.getLValueBase().get<const Expr *>();
  const CallExpr *CE = tryUnwrapAllocSizeCall(Base);
  return getBytesReturnedByAllocSizeCall(Ctx, CE, Result);
}

/// Attempts to evaluate the given LValueBase as the result of a call to
/// a function with the alloc_size attribute. If it was possible to do so, this
/// function will return true, make Result's Base point to said function call,
/// and mark Result's Base as invalid.
static bool evaluateLValueAsAllocSize(EvalInfo &Info, APValue::LValueBase Base,
                                      LValue &Result) {
  if (Base.isNull())
    return false;

  // Because we do no form of static analysis, we only support const variables.
  //
  // Additionally, we can't support parameters, nor can we support static
  // variables (in the latter case, use-before-assign isn't UB; in the former,
  // we have no clue what they'll be assigned to).
  const auto *VD =
      dyn_cast_or_null<VarDecl>(Base.dyn_cast<const ValueDecl *>());
  if (!VD || !VD->isLocalVarDecl() || !VD->getType().isConstQualified())
    return false;

  const Expr *Init = VD->getAnyInitializer();
  if (!Init)
    return false;

  const Expr *E = Init->IgnoreParens();
  if (!tryUnwrapAllocSizeCall(E))
    return false;

  // Store E instead of E unwrapped so that the type of the LValue's base is
  // what the user wanted.
  Result.setInvalid(E);

  QualType Pointee = E->getType()->castAs<PointerType>()->getPointeeType();
  Result.addUnsizedArray(Info, E, Pointee);
  return true;
}

namespace {
class PointerExprEvaluator
  : public ExprEvaluatorBase<PointerExprEvaluator> {
  LValue &Result;
  bool InvalidBaseOK;

  bool Success(const Expr *E) {
    Result.set(E);
    return true;
  }

  bool evaluateLValue(const Expr *E, LValue &Result) {
    return EvaluateLValue(E, Result, Info, InvalidBaseOK);
  }

  bool evaluatePointer(const Expr *E, LValue &Result) {
    return EvaluatePointer(E, Result, Info, InvalidBaseOK);
  }

  bool visitNonBuiltinCallExpr(const CallExpr *E);
public:

  PointerExprEvaluator(EvalInfo &info, LValue &Result, bool InvalidBaseOK)
      : ExprEvaluatorBaseTy(info), Result(Result),
        InvalidBaseOK(InvalidBaseOK) {}

  bool Success(const APValue &V, const Expr *E) {
    Result.setFrom(Info.Ctx, V);
    return true;
  }
  bool ZeroInitialization(const Expr *E) {
    Result.setNull(Info.Ctx, E->getType());
    return true;
  }

  bool VisitBinaryOperator(const BinaryOperator *E);
  bool VisitCastExpr(const CastExpr* E);
  bool VisitUnaryAddrOf(const UnaryOperator *E);
  bool VisitObjCStringLiteral(const ObjCStringLiteral *E)
      { return Success(E); }
  bool VisitObjCBoxedExpr(const ObjCBoxedExpr *E) {
    if (E->isExpressibleAsConstantInitializer())
      return Success(E);
    if (Info.noteFailure())
      EvaluateIgnoredValue(Info, E->getSubExpr());
    return Error(E);
  }
  bool VisitAddrLabelExpr(const AddrLabelExpr *E)
      { return Success(E); }
  bool VisitCallExpr(const CallExpr *E);
  bool VisitBuiltinCallExpr(const CallExpr *E, unsigned BuiltinOp);
  bool VisitBlockExpr(const BlockExpr *E) {
    if (!E->getBlockDecl()->hasCaptures())
      return Success(E);
    return Error(E);
  }
  bool VisitCXXThisExpr(const CXXThisExpr *E) {
    // Can't look at 'this' when checking a potential constant expression.
    if (Info.checkingPotentialConstantExpression())
      return false;
    if (!Info.CurrentCall->This) {
      if (Info.getLangOpts().CPlusPlus11)
        Info.FFDiag(E, diag::note_constexpr_this) << E->isImplicit();
      else
        Info.FFDiag(E);
      return false;
    }
    Result = *Info.CurrentCall->This;
    // If we are inside a lambda's call operator, the 'this' expression refers
    // to the enclosing '*this' object (either by value or reference) which is
    // either copied into the closure object's field that represents the '*this'
    // or refers to '*this'.
    if (isLambdaCallOperator(Info.CurrentCall->Callee)) {
      // Ensure we actually have captured 'this'. (an error will have
      // been previously reported if not).
      if (!Info.CurrentCall->LambdaThisCaptureField)
        return false;

      // Update 'Result' to refer to the data member/field of the closure object
      // that represents the '*this' capture.
      if (!HandleLValueMember(Info, E, Result,
                             Info.CurrentCall->LambdaThisCaptureField))
        return false;
      // If we captured '*this' by reference, replace the field with its referent.
      if (Info.CurrentCall->LambdaThisCaptureField->getType()
              ->isPointerType()) {
        APValue RVal;
        if (!handleLValueToRValueConversion(Info, E, E->getType(), Result,
                                            RVal))
          return false;

        Result.setFrom(Info.Ctx, RVal);
      }
    }
    return true;
  }

  bool VisitCXXNewExpr(const CXXNewExpr *E);

  bool VisitSourceLocExpr(const SourceLocExpr *E) {
    assert(E->isStringType() && "SourceLocExpr isn't a pointer type?");
    APValue LValResult = E->EvaluateInContext(
        Info.Ctx, Info.CurrentCall->CurSourceLocExprScope.getDefaultExpr());
    Result.setFrom(Info.Ctx, LValResult);
    return true;
  }

  // FIXME: Missing: @protocol, @selector
};
} // end anonymous namespace

static bool EvaluatePointer(const Expr* E, LValue& Result, EvalInfo &Info,
                            bool InvalidBaseOK) {
  assert(E->isRValue() && E->getType()->hasPointerRepresentation());
  return PointerExprEvaluator(Info, Result, InvalidBaseOK).Visit(E);
}

bool PointerExprEvaluator::VisitBinaryOperator(const BinaryOperator *E) {
  if (E->getOpcode() != BO_Add &&
      E->getOpcode() != BO_Sub)
    return ExprEvaluatorBaseTy::VisitBinaryOperator(E);

  const Expr *PExp = E->getLHS();
  const Expr *IExp = E->getRHS();
  if (IExp->getType()->isPointerType())
    std::swap(PExp, IExp);

  bool EvalPtrOK = evaluatePointer(PExp, Result);
  if (!EvalPtrOK && !Info.noteFailure())
    return false;

  llvm::APSInt Offset;
  if (!EvaluateInteger(IExp, Offset, Info) || !EvalPtrOK)
    return false;

  if (E->getOpcode() == BO_Sub)
    negateAsSigned(Offset);

  QualType Pointee = PExp->getType()->castAs<PointerType>()->getPointeeType();
  return HandleLValueArrayAdjustment(Info, E, Result, Pointee, Offset);
}

bool PointerExprEvaluator::VisitUnaryAddrOf(const UnaryOperator *E) {
  return evaluateLValue(E->getSubExpr(), Result);
}

bool PointerExprEvaluator::VisitCastExpr(const CastExpr *E) {
  const Expr *SubExpr = E->getSubExpr();

  switch (E->getCastKind()) {
  default:
    break;
  case CK_BitCast:
  case CK_CPointerToObjCPointerCast:
  case CK_BlockPointerToObjCPointerCast:
  case CK_AnyPointerToBlockPointerCast:
  case CK_AddressSpaceConversion:
    if (!Visit(SubExpr))
      return false;
    // Bitcasts to cv void* are static_casts, not reinterpret_casts, so are
    // permitted in constant expressions in C++11. Bitcasts from cv void* are
    // also static_casts, but we disallow them as a resolution to DR1312.
    if (!E->getType()->isVoidPointerType()) {
      if (!Result.InvalidBase && !Result.Designator.Invalid &&
          !Result.IsNullPtr &&
          Info.Ctx.hasSameUnqualifiedType(Result.Designator.getType(Info.Ctx),
                                          E->getType()->getPointeeType()) &&
          Info.getStdAllocatorCaller("allocate")) {
        // Inside a call to std::allocator::allocate and friends, we permit
        // casting from void* back to cv1 T* for a pointer that points to a
        // cv2 T.
      } else {
        Result.Designator.setInvalid();
        if (SubExpr->getType()->isVoidPointerType())
          CCEDiag(E, diag::note_constexpr_invalid_cast)
            << 3 << SubExpr->getType();
        else
          CCEDiag(E, diag::note_constexpr_invalid_cast) << 2;
      }
    }
    if (E->getCastKind() == CK_AddressSpaceConversion && Result.IsNullPtr)
      ZeroInitialization(E);
    return true;

  case CK_DerivedToBase:
  case CK_UncheckedDerivedToBase:
    if (!evaluatePointer(E->getSubExpr(), Result))
      return false;
    if (!Result.Base && Result.Offset.isZero())
      return true;

    // Now figure out the necessary offset to add to the base LV to get from
    // the derived class to the base class.
    return HandleLValueBasePath(Info, E, E->getSubExpr()->getType()->
                                  castAs<PointerType>()->getPointeeType(),
                                Result);

  case CK_BaseToDerived:
    if (!Visit(E->getSubExpr()))
      return false;
    if (!Result.Base && Result.Offset.isZero())
      return true;
    return HandleBaseToDerivedCast(Info, E, Result);

  case CK_Dynamic:
    if (!Visit(E->getSubExpr()))
      return false;
    return HandleDynamicCast(Info, cast<ExplicitCastExpr>(E), Result);

  case CK_NullToPointer:
    VisitIgnoredValue(E->getSubExpr());
    return ZeroInitialization(E);

  case CK_IntegralToPointer: {
    CCEDiag(E, diag::note_constexpr_invalid_cast) << 2;

    APValue Value;
    if (!EvaluateIntegerOrLValue(SubExpr, Value, Info))
      break;

    if (Value.isInt()) {
      unsigned Size = Info.Ctx.getTypeSize(E->getType());
      uint64_t N = Value.getInt().extOrTrunc(Size).getZExtValue();
      Result.Base = (Expr*)nullptr;
      Result.InvalidBase = false;
      Result.Offset = CharUnits::fromQuantity(N);
      Result.Designator.setInvalid();
      Result.IsNullPtr = false;
      return true;
    } else {
      // Cast is of an lvalue, no need to change value.
      Result.setFrom(Info.Ctx, Value);
      return true;
    }
  }

  case CK_ArrayToPointerDecay: {
    if (SubExpr->isGLValue()) {
      if (!evaluateLValue(SubExpr, Result))
        return false;
    } else {
      APValue &Value = Info.CurrentCall->createTemporary(
          SubExpr, SubExpr->getType(), false, Result);
      if (!EvaluateInPlace(Value, Info, Result, SubExpr))
        return false;
    }
    // The result is a pointer to the first element of the array.
    auto *AT = Info.Ctx.getAsArrayType(SubExpr->getType());
    if (auto *CAT = dyn_cast<ConstantArrayType>(AT))
      Result.addArray(Info, E, CAT);
    else
      Result.addUnsizedArray(Info, E, AT->getElementType());
    return true;
  }

  case CK_FunctionToPointerDecay:
    return evaluateLValue(SubExpr, Result);

  case CK_LValueToRValue: {
    LValue LVal;
    if (!evaluateLValue(E->getSubExpr(), LVal))
      return false;

    APValue RVal;
    // Note, we use the subexpression's type in order to retain cv-qualifiers.
    if (!handleLValueToRValueConversion(Info, E, E->getSubExpr()->getType(),
                                        LVal, RVal))
      return InvalidBaseOK &&
             evaluateLValueAsAllocSize(Info, LVal.Base, Result);
    return Success(RVal, E);
  }
  }

  return ExprEvaluatorBaseTy::VisitCastExpr(E);
}

static CharUnits GetAlignOfType(EvalInfo &Info, QualType T,
                                UnaryExprOrTypeTrait ExprKind) {
  // C++ [expr.alignof]p3:
  //     When alignof is applied to a reference type, the result is the
  //     alignment of the referenced type.
  if (const ReferenceType *Ref = T->getAs<ReferenceType>())
    T = Ref->getPointeeType();

  if (T.getQualifiers().hasUnaligned())
    return CharUnits::One();

  const bool AlignOfReturnsPreferred =
      Info.Ctx.getLangOpts().getClangABICompat() <= LangOptions::ClangABI::Ver7;

  // __alignof is defined to return the preferred alignment.
  // Before 8, clang returned the preferred alignment for alignof and _Alignof
  // as well.
  if (ExprKind == UETT_PreferredAlignOf || AlignOfReturnsPreferred)
    return Info.Ctx.toCharUnitsFromBits(
      Info.Ctx.getPreferredTypeAlign(T.getTypePtr()));
  // alignof and _Alignof are defined to return the ABI alignment.
  else if (ExprKind == UETT_AlignOf)
    return Info.Ctx.getTypeAlignInChars(T.getTypePtr());
  else
    llvm_unreachable("GetAlignOfType on a non-alignment ExprKind");
}

static CharUnits GetAlignOfExpr(EvalInfo &Info, const Expr *E,
                                UnaryExprOrTypeTrait ExprKind) {
  E = E->IgnoreParens();

  // The kinds of expressions that we have special-case logic here for
  // should be kept up to date with the special checks for those
  // expressions in Sema.

  // alignof decl is always accepted, even if it doesn't make sense: we default
  // to 1 in those cases.
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return Info.Ctx.getDeclAlign(DRE->getDecl(),
                                 /*RefAsPointee*/true);

  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E))
    return Info.Ctx.getDeclAlign(ME->getMemberDecl(),
                                 /*RefAsPointee*/true);

  return GetAlignOfType(Info, E->getType(), ExprKind);
}

static CharUnits getBaseAlignment(EvalInfo &Info, const LValue &Value) {
  if (const auto *VD = Value.Base.dyn_cast<const ValueDecl *>())
    return Info.Ctx.getDeclAlign(VD);
  if (const auto *E = Value.Base.dyn_cast<const Expr *>())
    return GetAlignOfExpr(Info, E, UETT_AlignOf);
  return GetAlignOfType(Info, Value.Base.getTypeInfoType(), UETT_AlignOf);
}

/// Evaluate the value of the alignment argument to __builtin_align_{up,down},
/// __builtin_is_aligned and __builtin_assume_aligned.
static bool getAlignmentArgument(const Expr *E, QualType ForType,
                                 EvalInfo &Info, APSInt &Alignment) {
  if (!EvaluateInteger(E, Alignment, Info))
    return false;
  if (Alignment < 0 || !Alignment.isPowerOf2()) {
    Info.FFDiag(E, diag::note_constexpr_invalid_alignment) << Alignment;
    return false;
  }
  unsigned SrcWidth = Info.Ctx.getIntWidth(ForType);
  APSInt MaxValue(APInt::getOneBitSet(SrcWidth, SrcWidth - 1));
  if (APSInt::compareValues(Alignment, MaxValue) > 0) {
    Info.FFDiag(E, diag::note_constexpr_alignment_too_big)
        << MaxValue << ForType << Alignment;
    return false;
  }
  // Ensure both alignment and source value have the same bit width so that we
  // don't assert when computing the resulting value.
  APSInt ExtAlignment =
      APSInt(Alignment.zextOrTrunc(SrcWidth), /*isUnsigned=*/true);
  assert(APSInt::compareValues(Alignment, ExtAlignment) == 0 &&
         "Alignment should not be changed by ext/trunc");
  Alignment = ExtAlignment;
  assert(Alignment.getBitWidth() == SrcWidth);
  return true;
}

// To be clear: this happily visits unsupported builtins. Better name welcomed.
bool PointerExprEvaluator::visitNonBuiltinCallExpr(const CallExpr *E) {
  if (ExprEvaluatorBaseTy::VisitCallExpr(E))
    return true;

  if (!(InvalidBaseOK && getAllocSizeAttr(E)))
    return false;

  Result.setInvalid(E);
  QualType PointeeTy = E->getType()->castAs<PointerType>()->getPointeeType();
  Result.addUnsizedArray(Info, E, PointeeTy);
  return true;
}

bool PointerExprEvaluator::VisitCallExpr(const CallExpr *E) {
  if (IsStringLiteralCall(E))
    return Success(E);

  if (unsigned BuiltinOp = E->getBuiltinCallee())
    return VisitBuiltinCallExpr(E, BuiltinOp);

  return visitNonBuiltinCallExpr(E);
}

bool PointerExprEvaluator::VisitBuiltinCallExpr(const CallExpr *E,
                                                unsigned BuiltinOp) {
  switch (BuiltinOp) {
  case Builtin::BI__builtin_addressof:
    return evaluateLValue(E->getArg(0), Result);
  case Builtin::BI__builtin_assume_aligned: {
    // We need to be very careful here because: if the pointer does not have the
    // asserted alignment, then the behavior is undefined, and undefined
    // behavior is non-constant.
    if (!evaluatePointer(E->getArg(0), Result))
      return false;

    LValue OffsetResult(Result);
    APSInt Alignment;
    if (!getAlignmentArgument(E->getArg(1), E->getArg(0)->getType(), Info,
                              Alignment))
      return false;
    CharUnits Align = CharUnits::fromQuantity(Alignment.getZExtValue());

    if (E->getNumArgs() > 2) {
      APSInt Offset;
      if (!EvaluateInteger(E->getArg(2), Offset, Info))
        return false;

      int64_t AdditionalOffset = -Offset.getZExtValue();
      OffsetResult.Offset += CharUnits::fromQuantity(AdditionalOffset);
    }

    // If there is a base object, then it must have the correct alignment.
    if (OffsetResult.Base) {
      CharUnits BaseAlignment = getBaseAlignment(Info, OffsetResult);

      if (BaseAlignment < Align) {
        Result.Designator.setInvalid();
        // FIXME: Add support to Diagnostic for long / long long.
        CCEDiag(E->getArg(0),
                diag::note_constexpr_baa_insufficient_alignment) << 0
          << (unsigned)BaseAlignment.getQuantity()
          << (unsigned)Align.getQuantity();
        return false;
      }
    }

    // The offset must also have the correct alignment.
    if (OffsetResult.Offset.alignTo(Align) != OffsetResult.Offset) {
      Result.Designator.setInvalid();

      (OffsetResult.Base
           ? CCEDiag(E->getArg(0),
                     diag::note_constexpr_baa_insufficient_alignment) << 1
           : CCEDiag(E->getArg(0),
                     diag::note_constexpr_baa_value_insufficient_alignment))
        << (int)OffsetResult.Offset.getQuantity()
        << (unsigned)Align.getQuantity();
      return false;
    }

    return true;
  }
  case Builtin::BI__builtin_align_up:
  case Builtin::BI__builtin_align_down: {
    if (!evaluatePointer(E->getArg(0), Result))
      return false;
    APSInt Alignment;
    if (!getAlignmentArgument(E->getArg(1), E->getArg(0)->getType(), Info,
                              Alignment))
      return false;
    CharUnits BaseAlignment = getBaseAlignment(Info, Result);
    CharUnits PtrAlign = BaseAlignment.alignmentAtOffset(Result.Offset);
    // For align_up/align_down, we can return the same value if the alignment
    // is known to be greater or equal to the requested value.
    if (PtrAlign.getQuantity() >= Alignment)
      return true;

    // The alignment could be greater than the minimum at run-time, so we cannot
    // infer much about the resulting pointer value. One case is possible:
    // For `_Alignas(32) char buf[N]; __builtin_align_down(&buf[idx], 32)` we
    // can infer the correct index if the requested alignment is smaller than
    // the base alignment so we can perform the computation on the offset.
    if (BaseAlignment.getQuantity() >= Alignment) {
      assert(Alignment.getBitWidth() <= 64 &&
             "Cannot handle > 64-bit address-space");
      uint64_t Alignment64 = Alignment.getZExtValue();
      CharUnits NewOffset = CharUnits::fromQuantity(
          BuiltinOp == Builtin::BI__builtin_align_down
              ? llvm::alignDown(Result.Offset.getQuantity(), Alignment64)
              : llvm::alignTo(Result.Offset.getQuantity(), Alignment64));
      Result.adjustOffset(NewOffset - Result.Offset);
      // TODO: diagnose out-of-bounds values/only allow for arrays?
      return true;
    }
    // Otherwise, we cannot constant-evaluate the result.
    Info.FFDiag(E->getArg(0), diag::note_constexpr_alignment_adjust)
        << Alignment;
    return false;
  }
  case Builtin::BI__builtin_operator_new:
    return HandleOperatorNewCall(Info, E, Result);
  case Builtin::BI__builtin_launder:
    return evaluatePointer(E->getArg(0), Result);
  case Builtin::BIstrchr:
  case Builtin::BIwcschr:
  case Builtin::BImemchr:
  case Builtin::BIwmemchr:
    if (Info.getLangOpts().CPlusPlus11)
      Info.CCEDiag(E, diag::note_constexpr_invalid_function)
        << /*isConstexpr*/0 << /*isConstructor*/0
        << (std::string("'") + Info.Ctx.BuiltinInfo.getName(BuiltinOp) + "'");
    else
      Info.CCEDiag(E, diag::note_invalid_subexpr_in_const_expr);
    LLVM_FALLTHROUGH;
  case Builtin::BI__builtin_strchr:
  case Builtin::BI__builtin_wcschr:
  case Builtin::BI__builtin_memchr:
  case Builtin::BI__builtin_char_memchr:
  case Builtin::BI__builtin_wmemchr: {
    if (!Visit(E->getArg(0)))
      return false;
    APSInt Desired;
    if (!EvaluateInteger(E->getArg(1), Desired, Info))
      return false;
    uint64_t MaxLength = uint64_t(-1);
    if (BuiltinOp != Builtin::BIstrchr &&
        BuiltinOp != Builtin::BIwcschr &&
        BuiltinOp != Builtin::BI__builtin_strchr &&
        BuiltinOp != Builtin::BI__builtin_wcschr) {
      APSInt N;
      if (!EvaluateInteger(E->getArg(2), N, Info))
        return false;
      MaxLength = N.getExtValue();
    }
    // We cannot find the value if there are no candidates to match against.
    if (MaxLength == 0u)
      return ZeroInitialization(E);
    if (!Result.checkNullPointerForFoldAccess(Info, E, AK_Read) ||
        Result.Designator.Invalid)
      return false;
    QualType CharTy = Result.Designator.getType(Info.Ctx);
    bool IsRawByte = BuiltinOp == Builtin::BImemchr ||
                     BuiltinOp == Builtin::BI__builtin_memchr;
    assert(IsRawByte ||
           Info.Ctx.hasSameUnqualifiedType(
               CharTy, E->getArg(0)->getType()->getPointeeType()));
    // Pointers to const void may point to objects of incomplete type.
    if (IsRawByte && CharTy->isIncompleteType()) {
      Info.FFDiag(E, diag::note_constexpr_ltor_incomplete_type) << CharTy;
      return false;
    }
    // Give up on byte-oriented matching against multibyte elements.
    // FIXME: We can compare the bytes in the correct order.
    if (IsRawByte && Info.Ctx.getTypeSizeInChars(CharTy) != CharUnits::One())
      return false;
    // Figure out what value we're actually looking for (after converting to
    // the corresponding unsigned type if necessary).
    uint64_t DesiredVal;
    bool StopAtNull = false;
    switch (BuiltinOp) {
    case Builtin::BIstrchr:
    case Builtin::BI__builtin_strchr:
      // strchr compares directly to the passed integer, and therefore
      // always fails if given an int that is not a char.
      if (!APSInt::isSameValue(HandleIntToIntCast(Info, E, CharTy,
                                                  E->getArg(1)->getType(),
                                                  Desired),
                               Desired))
        return ZeroInitialization(E);
      StopAtNull = true;
      LLVM_FALLTHROUGH;
    case Builtin::BImemchr:
    case Builtin::BI__builtin_memchr:
    case Builtin::BI__builtin_char_memchr:
      // memchr compares by converting both sides to unsigned char. That's also
      // correct for strchr if we get this far (to cope with plain char being
      // unsigned in the strchr case).
      DesiredVal = Desired.trunc(Info.Ctx.getCharWidth()).getZExtValue();
      break;

    case Builtin::BIwcschr:
    case Builtin::BI__builtin_wcschr:
      StopAtNull = true;
      LLVM_FALLTHROUGH;
    case Builtin::BIwmemchr:
    case Builtin::BI__builtin_wmemchr:
      // wcschr and wmemchr are given a wchar_t to look for. Just use it.
      DesiredVal = Desired.getZExtValue();
      break;
    }

    for (; MaxLength; --MaxLength) {
      APValue Char;
      if (!handleLValueToRValueConversion(Info, E, CharTy, Result, Char) ||
          !Char.isInt())
        return false;
      if (Char.getInt().getZExtValue() == DesiredVal)
        return true;
      if (StopAtNull && !Char.getInt())
        break;
      if (!HandleLValueArrayAdjustment(Info, E, Result, CharTy, 1))
        return false;
    }
    // Not found: return nullptr.
    return ZeroInitialization(E);
  }

  case Builtin::BImemcpy:
  case Builtin::BImemmove:
  case Builtin::BIwmemcpy:
  case Builtin::BIwmemmove:
    if (Info.getLangOpts().CPlusPlus11)
      Info.CCEDiag(E, diag::note_constexpr_invalid_function)
        << /*isConstexpr*/0 << /*isConstructor*/0
        << (std::string("'") + Info.Ctx.BuiltinInfo.getName(BuiltinOp) + "'");
    else
      Info.CCEDiag(E, diag::note_invalid_subexpr_in_const_expr);
    LLVM_FALLTHROUGH;
  case Builtin::BI__builtin_memcpy:
  case Builtin::BI__builtin_memmove:
  case Builtin::BI__builtin_wmemcpy:
  case Builtin::BI__builtin_wmemmove: {
    bool WChar = BuiltinOp == Builtin::BIwmemcpy ||
                 BuiltinOp == Builtin::BIwmemmove ||
                 BuiltinOp == Builtin::BI__builtin_wmemcpy ||
                 BuiltinOp == Builtin::BI__builtin_wmemmove;
    bool Move = BuiltinOp == Builtin::BImemmove ||
                BuiltinOp == Builtin::BIwmemmove ||
                BuiltinOp == Builtin::BI__builtin_memmove ||
                BuiltinOp == Builtin::BI__builtin_wmemmove;

    // The result of mem* is the first argument.
    if (!Visit(E->getArg(0)))
      return false;
    LValue Dest = Result;

    LValue Src;
    if (!EvaluatePointer(E->getArg(1), Src, Info))
      return false;

    APSInt N;
    if (!EvaluateInteger(E->getArg(2), N, Info))
      return false;
    assert(!N.isSigned() && "memcpy and friends take an unsigned size");

    // If the size is zero, we treat this as always being a valid no-op.
    // (Even if one of the src and dest pointers is null.)
    if (!N)
      return true;

    // Otherwise, if either of the operands is null, we can't proceed. Don't
    // try to determine the type of the copied objects, because there aren't
    // any.
    if (!Src.Base || !Dest.Base) {
      APValue Val;
      (!Src.Base ? Src : Dest).moveInto(Val);
      Info.FFDiag(E, diag::note_constexpr_memcpy_null)
          << Move << WChar << !!Src.Base
          << Val.getAsString(Info.Ctx, E->getArg(0)->getType());
      return false;
    }
    if (Src.Designator.Invalid || Dest.Designator.Invalid)
      return false;

    // We require that Src and Dest are both pointers to arrays of
    // trivially-copyable type. (For the wide version, the designator will be
    // invalid if the designated object is not a wchar_t.)
    QualType T = Dest.Designator.getType(Info.Ctx);
    QualType SrcT = Src.Designator.getType(Info.Ctx);
    if (!Info.Ctx.hasSameUnqualifiedType(T, SrcT)) {
      Info.FFDiag(E, diag::note_constexpr_memcpy_type_pun) << Move << SrcT << T;
      return false;
    }
    if (T->isIncompleteType()) {
      Info.FFDiag(E, diag::note_constexpr_memcpy_incomplete_type) << Move << T;
      return false;
    }
    if (!T.isTriviallyCopyableType(Info.Ctx)) {
      Info.FFDiag(E, diag::note_constexpr_memcpy_nontrivial) << Move << T;
      return false;
    }

    // Figure out how many T's we're copying.
    uint64_t TSize = Info.Ctx.getTypeSizeInChars(T).getQuantity();
    if (!WChar) {
      uint64_t Remainder;
      llvm::APInt OrigN = N;
      llvm::APInt::udivrem(OrigN, TSize, N, Remainder);
      if (Remainder) {
        Info.FFDiag(E, diag::note_constexpr_memcpy_unsupported)
            << Move << WChar << 0 << T << OrigN.toString(10, /*Signed*/false)
            << (unsigned)TSize;
        return false;
      }
    }

    // Check that the copying will remain within the arrays, just so that we
    // can give a more meaningful diagnostic. This implicitly also checks that
    // N fits into 64 bits.
    uint64_t RemainingSrcSize = Src.Designator.validIndexAdjustments().second;
    uint64_t RemainingDestSize = Dest.Designator.validIndexAdjustments().second;
    if (N.ugt(RemainingSrcSize) || N.ugt(RemainingDestSize)) {
      Info.FFDiag(E, diag::note_constexpr_memcpy_unsupported)
          << Move << WChar << (N.ugt(RemainingSrcSize) ? 1 : 2) << T
          << N.toString(10, /*Signed*/false);
      return false;
    }
    uint64_t NElems = N.getZExtValue();
    uint64_t NBytes = NElems * TSize;

    // Check for overlap.
    int Direction = 1;
    if (HasSameBase(Src, Dest)) {
      uint64_t SrcOffset = Src.getLValueOffset().getQuantity();
      uint64_t DestOffset = Dest.getLValueOffset().getQuantity();
      if (DestOffset >= SrcOffset && DestOffset - SrcOffset < NBytes) {
        // Dest is inside the source region.
        if (!Move) {
          Info.FFDiag(E, diag::note_constexpr_memcpy_overlap) << WChar;
          return false;
        }
        // For memmove and friends, copy backwards.
        if (!HandleLValueArrayAdjustment(Info, E, Src, T, NElems - 1) ||
            !HandleLValueArrayAdjustment(Info, E, Dest, T, NElems - 1))
          return false;
        Direction = -1;
      } else if (!Move && SrcOffset >= DestOffset &&
                 SrcOffset - DestOffset < NBytes) {
        // Src is inside the destination region for memcpy: invalid.
        Info.FFDiag(E, diag::note_constexpr_memcpy_overlap) << WChar;
        return false;
      }
    }

    while (true) {
      APValue Val;
      // FIXME: Set WantObjectRepresentation to true if we're copying a
      // char-like type?
      if (!handleLValueToRValueConversion(Info, E, T, Src, Val) ||
          !handleAssignment(Info, E, Dest, T, Val))
        return false;
      // Do not iterate past the last element; if we're copying backwards, that
      // might take us off the start of the array.
      if (--NElems == 0)
        return true;
      if (!HandleLValueArrayAdjustment(Info, E, Src, T, Direction) ||
          !HandleLValueArrayAdjustment(Info, E, Dest, T, Direction))
        return false;
    }
  }

  default:
    break;
  }

  return visitNonBuiltinCallExpr(E);
}

static bool EvaluateArrayNewInitList(EvalInfo &Info, LValue &This,
                                     APValue &Result, const InitListExpr *ILE,
                                     QualType AllocType);
static bool EvaluateArrayNewConstructExpr(EvalInfo &Info, LValue &This,
                                          APValue &Result,
                                          const CXXConstructExpr *CCE,
                                          QualType AllocType);

bool PointerExprEvaluator::VisitCXXNewExpr(const CXXNewExpr *E) {
  if (!Info.getLangOpts().CPlusPlus2a)
    Info.CCEDiag(E, diag::note_constexpr_new);

  // We cannot speculatively evaluate a delete expression.
  if (Info.SpeculativeEvaluationDepth)
    return false;

  FunctionDecl *OperatorNew = E->getOperatorNew();

  bool IsNothrow = false;
  bool IsPlacement = false;
  if (OperatorNew->isReservedGlobalPlacementOperator() &&
      Info.CurrentCall->isStdFunction() && !E->isArray()) {
    // FIXME Support array placement new.
    assert(E->getNumPlacementArgs() == 1);
    if (!EvaluatePointer(E->getPlacementArg(0), Result, Info))
      return false;
    if (Result.Designator.Invalid)
      return false;
    IsPlacement = true;
  } else if (!OperatorNew->isReplaceableGlobalAllocationFunction()) {
    Info.FFDiag(E, diag::note_constexpr_new_non_replaceable)
        << isa<CXXMethodDecl>(OperatorNew) << OperatorNew;
    return false;
  } else if (E->getNumPlacementArgs()) {
    // The only new-placement list we support is of the form (std::nothrow).
    //
    // FIXME: There is no restriction on this, but it's not clear that any
    // other form makes any sense. We get here for cases such as:
    //
    //   new (std::align_val_t{N}) X(int)
    //
    // (which should presumably be valid only if N is a multiple of
    // alignof(int), and in any case can't be deallocated unless N is
    // alignof(X) and X has new-extended alignment).
    if (E->getNumPlacementArgs() != 1 ||
        !E->getPlacementArg(0)->getType()->isNothrowT())
      return Error(E, diag::note_constexpr_new_placement);

    LValue Nothrow;
    if (!EvaluateLValue(E->getPlacementArg(0), Nothrow, Info))
      return false;
    IsNothrow = true;
  }

  const Expr *Init = E->getInitializer();
  const InitListExpr *ResizedArrayILE = nullptr;
  const CXXConstructExpr *ResizedArrayCCE = nullptr;

  QualType AllocType = E->getAllocatedType();
  if (Optional<const Expr*> ArraySize = E->getArraySize()) {
    const Expr *Stripped = *ArraySize;
    for (; auto *ICE = dyn_cast<ImplicitCastExpr>(Stripped);
         Stripped = ICE->getSubExpr())
      if (ICE->getCastKind() != CK_NoOp &&
          ICE->getCastKind() != CK_IntegralCast)
        break;

    llvm::APSInt ArrayBound;
    if (!EvaluateInteger(Stripped, ArrayBound, Info))
      return false;

    // C++ [expr.new]p9:
    //   The expression is erroneous if:
    //   -- [...] its value before converting to size_t [or] applying the
    //      second standard conversion sequence is less than zero
    if (ArrayBound.isSigned() && ArrayBound.isNegative()) {
      if (IsNothrow)
        return ZeroInitialization(E);

      Info.FFDiag(*ArraySize, diag::note_constexpr_new_negative)
          << ArrayBound << (*ArraySize)->getSourceRange();
      return false;
    }

    //   -- its value is such that the size of the allocated object would
    //      exceed the implementation-defined limit
    if (ConstantArrayType::getNumAddressingBits(Info.Ctx, AllocType,
                                                ArrayBound) >
        ConstantArrayType::getMaxSizeBits(Info.Ctx)) {
      if (IsNothrow)
        return ZeroInitialization(E);

      Info.FFDiag(*ArraySize, diag::note_constexpr_new_too_large)
        << ArrayBound << (*ArraySize)->getSourceRange();
      return false;
    }

    //   -- the new-initializer is a braced-init-list and the number of
    //      array elements for which initializers are provided [...]
    //      exceeds the number of elements to initialize
    if (Init && !isa<CXXConstructExpr>(Init)) {
      auto *CAT = Info.Ctx.getAsConstantArrayType(Init->getType());
      assert(CAT && "unexpected type for array initializer");

      unsigned Bits =
          std::max(CAT->getSize().getBitWidth(), ArrayBound.getBitWidth());
      llvm::APInt InitBound = CAT->getSize().zextOrSelf(Bits);
      llvm::APInt AllocBound = ArrayBound.zextOrSelf(Bits);
      if (InitBound.ugt(AllocBound)) {
        if (IsNothrow)
          return ZeroInitialization(E);

        Info.FFDiag(*ArraySize, diag::note_constexpr_new_too_small)
            << AllocBound.toString(10, /*Signed=*/false)
            << InitBound.toString(10, /*Signed=*/false)
            << (*ArraySize)->getSourceRange();
        return false;
      }

      // If the sizes differ, we must have an initializer list, and we need
      // special handling for this case when we initialize.
      if (InitBound != AllocBound)
        ResizedArrayILE = cast<InitListExpr>(Init);
      } else if (Init) {
        ResizedArrayCCE = cast<CXXConstructExpr>(Init);
    }

    AllocType = Info.Ctx.getConstantArrayType(AllocType, ArrayBound, nullptr,
                                              ArrayType::Normal, 0);
  } else {
    assert(!AllocType->isArrayType() &&
           "array allocation with non-array new");
  }

  APValue *Val;
  if (IsPlacement) {
    AccessKinds AK = AK_Construct;
    struct FindObjectHandler {
      EvalInfo &Info;
      const Expr *E;
      QualType AllocType;
      const AccessKinds AccessKind;
      APValue *Value;

      typedef bool result_type;
      bool failed() { return false; }
      bool found(APValue &Subobj, QualType SubobjType) {
        // FIXME: Reject the cases where [basic.life]p8 would not permit the
        // old name of the object to be used to name the new object.
        if (!Info.Ctx.hasSameUnqualifiedType(SubobjType, AllocType)) {
          Info.FFDiag(E, diag::note_constexpr_placement_new_wrong_type) <<
            SubobjType << AllocType;
          return false;
        }
        Value = &Subobj;
        return true;
      }
      bool found(APSInt &Value, QualType SubobjType) {
        Info.FFDiag(E, diag::note_constexpr_construct_complex_elem);
        return false;
      }
      bool found(APFloat &Value, QualType SubobjType) {
        Info.FFDiag(E, diag::note_constexpr_construct_complex_elem);
        return false;
      }
    } Handler = {Info, E, AllocType, AK, nullptr};

    CompleteObject Obj = findCompleteObject(Info, E, AK, Result, AllocType);
    if (!Obj || !findSubobject(Info, E, Obj, Result.Designator, Handler))
      return false;

    Val = Handler.Value;

    // [basic.life]p1:
    //   The lifetime of an object o of type T ends when [...] the storage
    //   which the object occupies is [...] reused by an object that is not
    //   nested within o (6.6.2).
    *Val = APValue();
  } else {
    // Perform the allocation and obtain a pointer to the resulting object.
    Val = Info.createHeapAlloc(E, AllocType, Result);
    if (!Val)
      return false;
  }

  if (ResizedArrayILE) {
    if (!EvaluateArrayNewInitList(Info, Result, *Val, ResizedArrayILE,
                                  AllocType))
      return false;
  } else if (ResizedArrayCCE) {
    if (!EvaluateArrayNewConstructExpr(Info, Result, *Val, ResizedArrayCCE,
                                       AllocType))
      return false;
  } else if (Init) {
    if (!EvaluateInPlace(*Val, Info, Result, Init))
      return false;
  } else {
    *Val = getDefaultInitValue(AllocType);
  }

  // Array new returns a pointer to the first element, not a pointer to the
  // array.
  if (auto *AT = AllocType->getAsArrayTypeUnsafe())
    Result.addArray(Info, E, cast<ConstantArrayType>(AT));

  return true;
}
//===----------------------------------------------------------------------===//
// Member Pointer Evaluation
//===----------------------------------------------------------------------===//

namespace {
class MemberPointerExprEvaluator
  : public ExprEvaluatorBase<MemberPointerExprEvaluator> {
  MemberPtr &Result;

  bool Success(const ValueDecl *D) {
    Result = MemberPtr(D);
    return true;
  }
public:

  MemberPointerExprEvaluator(EvalInfo &Info, MemberPtr &Result)
    : ExprEvaluatorBaseTy(Info), Result(Result) {}

  bool Success(const APValue &V, const Expr *E) {
    Result.setFrom(V);
    return true;
  }
  bool ZeroInitialization(const Expr *E) {
    return Success((const ValueDecl*)nullptr);
  }

  bool VisitCastExpr(const CastExpr *E);
  bool VisitUnaryAddrOf(const UnaryOperator *E);
};
} // end anonymous namespace

static bool EvaluateMemberPointer(const Expr *E, MemberPtr &Result,
                                  EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isMemberPointerType());
  return MemberPointerExprEvaluator(Info, Result).Visit(E);
}

bool MemberPointerExprEvaluator::VisitCastExpr(const CastExpr *E) {
  switch (E->getCastKind()) {
  default:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);

  case CK_NullToMemberPointer:
    VisitIgnoredValue(E->getSubExpr());
    return ZeroInitialization(E);

  case CK_BaseToDerivedMemberPointer: {
    if (!Visit(E->getSubExpr()))
      return false;
    if (E->path_empty())
      return true;
    // Base-to-derived member pointer casts store the path in derived-to-base
    // order, so iterate backwards. The CXXBaseSpecifier also provides us with
    // the wrong end of the derived->base arc, so stagger the path by one class.
    typedef std::reverse_iterator<CastExpr::path_const_iterator> ReverseIter;
    for (ReverseIter PathI(E->path_end() - 1), PathE(E->path_begin());
         PathI != PathE; ++PathI) {
      assert(!(*PathI)->isVirtual() && "memptr cast through vbase");
      const CXXRecordDecl *Derived = (*PathI)->getType()->getAsCXXRecordDecl();
      if (!Result.castToDerived(Derived))
        return Error(E);
    }
    const Type *FinalTy = E->getType()->castAs<MemberPointerType>()->getClass();
    if (!Result.castToDerived(FinalTy->getAsCXXRecordDecl()))
      return Error(E);
    return true;
  }

  case CK_DerivedToBaseMemberPointer:
    if (!Visit(E->getSubExpr()))
      return false;
    for (CastExpr::path_const_iterator PathI = E->path_begin(),
         PathE = E->path_end(); PathI != PathE; ++PathI) {
      assert(!(*PathI)->isVirtual() && "memptr cast through vbase");
      const CXXRecordDecl *Base = (*PathI)->getType()->getAsCXXRecordDecl();
      if (!Result.castToBase(Base))
        return Error(E);
    }
    return true;
  }
}

bool MemberPointerExprEvaluator::VisitUnaryAddrOf(const UnaryOperator *E) {
  // C++11 [expr.unary.op]p3 has very strict rules on how the address of a
  // member can be formed.
  return Success(cast<DeclRefExpr>(E->getSubExpr())->getDecl());
}

//===----------------------------------------------------------------------===//
// Record Evaluation
//===----------------------------------------------------------------------===//

namespace {
  class RecordExprEvaluator
  : public ExprEvaluatorBase<RecordExprEvaluator> {
    const LValue &This;
    APValue &Result;
  public:

    RecordExprEvaluator(EvalInfo &info, const LValue &This, APValue &Result)
      : ExprEvaluatorBaseTy(info), This(This), Result(Result) {}

    bool Success(const APValue &V, const Expr *E) {
      Result = V;
      return true;
    }
    bool ZeroInitialization(const Expr *E) {
      return ZeroInitialization(E, E->getType());
    }
    bool ZeroInitialization(const Expr *E, QualType T);

    bool VisitCallExpr(const CallExpr *E) {
      return handleCallExpr(E, Result, &This);
    }
    bool VisitCastExpr(const CastExpr *E);
    bool VisitInitListExpr(const InitListExpr *E);
    bool VisitCXXConstructExpr(const CXXConstructExpr *E) {
      return VisitCXXConstructExpr(E, E->getType());
    }
    bool VisitLambdaExpr(const LambdaExpr *E);
    bool VisitCXXInheritedCtorInitExpr(const CXXInheritedCtorInitExpr *E);
    bool VisitCXXConstructExpr(const CXXConstructExpr *E, QualType T);
    bool VisitCXXStdInitializerListExpr(const CXXStdInitializerListExpr *E);
    bool VisitBinCmp(const BinaryOperator *E);
  };
}

/// Perform zero-initialization on an object of non-union class type.
/// C++11 [dcl.init]p5:
///  To zero-initialize an object or reference of type T means:
///    [...]
///    -- if T is a (possibly cv-qualified) non-union class type,
///       each non-static data member and each base-class subobject is
///       zero-initialized
static bool HandleClassZeroInitialization(EvalInfo &Info, const Expr *E,
                                          const RecordDecl *RD,
                                          const LValue &This, APValue &Result) {
  assert(!RD->isUnion() && "Expected non-union class type");
  const CXXRecordDecl *CD = dyn_cast<CXXRecordDecl>(RD);
  Result = APValue(APValue::UninitStruct(), CD ? CD->getNumBases() : 0,
                   std::distance(RD->field_begin(), RD->field_end()));

  if (RD->isInvalidDecl()) return false;
  const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);

  if (CD) {
    unsigned Index = 0;
    for (CXXRecordDecl::base_class_const_iterator I = CD->bases_begin(),
           End = CD->bases_end(); I != End; ++I, ++Index) {
      const CXXRecordDecl *Base = I->getType()->getAsCXXRecordDecl();
      LValue Subobject = This;
      if (!HandleLValueDirectBase(Info, E, Subobject, CD, Base, &Layout))
        return false;
      if (!HandleClassZeroInitialization(Info, E, Base, Subobject,
                                         Result.getStructBase(Index)))
        return false;
    }
  }

  for (const auto *I : RD->fields()) {
    // -- if T is a reference type, no initialization is performed.
    if (I->getType()->isReferenceType())
      continue;

    LValue Subobject = This;
    if (!HandleLValueMember(Info, E, Subobject, I, &Layout))
      return false;

    ImplicitValueInitExpr VIE(I->getType());
    if (!EvaluateInPlace(
          Result.getStructField(I->getFieldIndex()), Info, Subobject, &VIE))
      return false;
  }

  return true;
}

bool RecordExprEvaluator::ZeroInitialization(const Expr *E, QualType T) {
  const RecordDecl *RD = T->castAs<RecordType>()->getDecl();
  if (RD->isInvalidDecl()) return false;
  if (RD->isUnion()) {
    // C++11 [dcl.init]p5: If T is a (possibly cv-qualified) union type, the
    // object's first non-static named data member is zero-initialized
    RecordDecl::field_iterator I = RD->field_begin();
    if (I == RD->field_end()) {
      Result = APValue((const FieldDecl*)nullptr);
      return true;
    }

    LValue Subobject = This;
    if (!HandleLValueMember(Info, E, Subobject, *I))
      return false;
    Result = APValue(*I);
    ImplicitValueInitExpr VIE(I->getType());
    return EvaluateInPlace(Result.getUnionValue(), Info, Subobject, &VIE);
  }

  if (isa<CXXRecordDecl>(RD) && cast<CXXRecordDecl>(RD)->getNumVBases()) {
    Info.FFDiag(E, diag::note_constexpr_virtual_base) << RD;
    return false;
  }

  return HandleClassZeroInitialization(Info, E, RD, This, Result);
}

bool RecordExprEvaluator::VisitCastExpr(const CastExpr *E) {
  switch (E->getCastKind()) {
  default:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);

  case CK_ConstructorConversion:
    return Visit(E->getSubExpr());

  case CK_DerivedToBase:
  case CK_UncheckedDerivedToBase: {
    APValue DerivedObject;
    if (!Evaluate(DerivedObject, Info, E->getSubExpr()))
      return false;
    if (!DerivedObject.isStruct())
      return Error(E->getSubExpr());

    // Derived-to-base rvalue conversion: just slice off the derived part.
    APValue *Value = &DerivedObject;
    const CXXRecordDecl *RD = E->getSubExpr()->getType()->getAsCXXRecordDecl();
    for (CastExpr::path_const_iterator PathI = E->path_begin(),
         PathE = E->path_end(); PathI != PathE; ++PathI) {
      assert(!(*PathI)->isVirtual() && "record rvalue with virtual base");
      const CXXRecordDecl *Base = (*PathI)->getType()->getAsCXXRecordDecl();
      Value = &Value->getStructBase(getBaseIndex(RD, Base));
      RD = Base;
    }
    Result = *Value;
    return true;
  }
  }
}

bool RecordExprEvaluator::VisitInitListExpr(const InitListExpr *E) {
  if (E->isTransparent())
    return Visit(E->getInit(0));

  const RecordDecl *RD = E->getType()->castAs<RecordType>()->getDecl();
  if (RD->isInvalidDecl()) return false;
  const ASTRecordLayout &Layout = Info.Ctx.getASTRecordLayout(RD);
  auto *CXXRD = dyn_cast<CXXRecordDecl>(RD);

  EvalInfo::EvaluatingConstructorRAII EvalObj(
      Info,
      ObjectUnderConstruction{This.getLValueBase(), This.Designator.Entries},
      CXXRD && CXXRD->getNumBases());

  if (RD->isUnion()) {
    const FieldDecl *Field = E->getInitializedFieldInUnion();
    Result = APValue(Field);
    if (!Field)
      return true;

    // If the initializer list for a union does not contain any elements, the
    // first element of the union is value-initialized.
    // FIXME: The element should be initialized from an initializer list.
    //        Is this difference ever observable for initializer lists which
    //        we don't build?
    ImplicitValueInitExpr VIE(Field->getType());
    const Expr *InitExpr = E->getNumInits() ? E->getInit(0) : &VIE;

    LValue Subobject = This;
    if (!HandleLValueMember(Info, InitExpr, Subobject, Field, &Layout))
      return false;

    // Temporarily override This, in case there's a CXXDefaultInitExpr in here.
    ThisOverrideRAII ThisOverride(*Info.CurrentCall, &This,
                                  isa<CXXDefaultInitExpr>(InitExpr));

    return EvaluateInPlace(Result.getUnionValue(), Info, Subobject, InitExpr);
  }

  if (!Result.hasValue())
    Result = APValue(APValue::UninitStruct(), CXXRD ? CXXRD->getNumBases() : 0,
                     std::distance(RD->field_begin(), RD->field_end()));
  unsigned ElementNo = 0;
  bool Success = true;

  // Initialize base classes.
  if (CXXRD && CXXRD->getNumBases()) {
    for (const auto &Base : CXXRD->bases()) {
      assert(ElementNo < E->getNumInits() && "missing init for base class");
      const Expr *Init = E->getInit(ElementNo);

      LValue Subobject = This;
      if (!HandleLValueBase(Info, Init, Subobject, CXXRD, &Base))
        return false;

      APValue &FieldVal = Result.getStructBase(ElementNo);
      if (!EvaluateInPlace(FieldVal, Info, Subobject, Init)) {
        if (!Info.noteFailure())
          return false;
        Success = false;
      }
      ++ElementNo;
    }

    EvalObj.finishedConstructingBases();
  }

  // Initialize members.
  for (const auto *Field : RD->fields()) {
    // Anonymous bit-fields are not considered members of the class for
    // purposes of aggregate initialization.
    if (Field->isUnnamedBitfield())
      continue;

    LValue Subobject = This;

    bool HaveInit = ElementNo < E->getNumInits();

    // FIXME: Diagnostics here should point to the end of the initializer
    // list, not the start.
    if (!HandleLValueMember(Info, HaveInit ? E->getInit(ElementNo) : E,
                            Subobject, Field, &Layout))
      return false;

    // Perform an implicit value-initialization for members beyond the end of
    // the initializer list.
    ImplicitValueInitExpr VIE(HaveInit ? Info.Ctx.IntTy : Field->getType());
    const Expr *Init = HaveInit ? E->getInit(ElementNo++) : &VIE;

    // Temporarily override This, in case there's a CXXDefaultInitExpr in here.
    ThisOverrideRAII ThisOverride(*Info.CurrentCall, &This,
                                  isa<CXXDefaultInitExpr>(Init));

    APValue &FieldVal = Result.getStructField(Field->getFieldIndex());
    if (!EvaluateInPlace(FieldVal, Info, Subobject, Init) ||
        (Field->isBitField() && !truncateBitfieldValue(Info, Init,
                                                       FieldVal, Field))) {
      if (!Info.noteFailure())
        return false;
      Success = false;
    }
  }

  return Success;
}

bool RecordExprEvaluator::VisitCXXConstructExpr(const CXXConstructExpr *E,
                                                QualType T) {
  // Note that E's type is not necessarily the type of our class here; we might
  // be initializing an array element instead.
  const CXXConstructorDecl *FD = E->getConstructor();
  if (FD->isInvalidDecl() || FD->getParent()->isInvalidDecl()) return false;

  bool ZeroInit = E->requiresZeroInitialization();
  if (CheckTrivialDefaultConstructor(Info, E->getExprLoc(), FD, ZeroInit)) {
    // If we've already performed zero-initialization, we're already done.
    if (Result.hasValue())
      return true;

    if (ZeroInit)
      return ZeroInitialization(E, T);

    Result = getDefaultInitValue(T);
    return true;
  }

  const FunctionDecl *Definition = nullptr;
  auto Body = FD->getBody(Definition);

  if (!CheckConstexprFunction(Info, E->getExprLoc(), FD, Definition, Body))
    return false;

  // Avoid materializing a temporary for an elidable copy/move constructor.
  if (E->isElidable() && !ZeroInit)
    if (const MaterializeTemporaryExpr *ME
          = dyn_cast<MaterializeTemporaryExpr>(E->getArg(0)))
      return Visit(ME->getSubExpr());

  if (ZeroInit && !ZeroInitialization(E, T))
    return false;

  auto Args = llvm::makeArrayRef(E->getArgs(), E->getNumArgs());
  return HandleConstructorCall(E, This, Args,
                               cast<CXXConstructorDecl>(Definition), Info,
                               Result);
}

bool RecordExprEvaluator::VisitCXXInheritedCtorInitExpr(
    const CXXInheritedCtorInitExpr *E) {
  if (!Info.CurrentCall) {
    assert(Info.checkingPotentialConstantExpression());
    return false;
  }

  const CXXConstructorDecl *FD = E->getConstructor();
  if (FD->isInvalidDecl() || FD->getParent()->isInvalidDecl())
    return false;

  const FunctionDecl *Definition = nullptr;
  auto Body = FD->getBody(Definition);

  if (!CheckConstexprFunction(Info, E->getExprLoc(), FD, Definition, Body))
    return false;

  return HandleConstructorCall(E, This, Info.CurrentCall->Arguments,
                               cast<CXXConstructorDecl>(Definition), Info,
                               Result);
}

bool RecordExprEvaluator::VisitCXXStdInitializerListExpr(
    const CXXStdInitializerListExpr *E) {
  const ConstantArrayType *ArrayType =
      Info.Ctx.getAsConstantArrayType(E->getSubExpr()->getType());

  LValue Array;
  if (!EvaluateLValue(E->getSubExpr(), Array, Info))
    return false;

  // Get a pointer to the first element of the array.
  Array.addArray(Info, E, ArrayType);

  // FIXME: Perform the checks on the field types in SemaInit.
  RecordDecl *Record = E->getType()->castAs<RecordType>()->getDecl();
  RecordDecl::field_iterator Field = Record->field_begin();
  if (Field == Record->field_end())
    return Error(E);

  // Start pointer.
  if (!Field->getType()->isPointerType() ||
      !Info.Ctx.hasSameType(Field->getType()->getPointeeType(),
                            ArrayType->getElementType()))
    return Error(E);

  // FIXME: What if the initializer_list type has base classes, etc?
  Result = APValue(APValue::UninitStruct(), 0, 2);
  Array.moveInto(Result.getStructField(0));

  if (++Field == Record->field_end())
    return Error(E);

  if (Field->getType()->isPointerType() &&
      Info.Ctx.hasSameType(Field->getType()->getPointeeType(),
                           ArrayType->getElementType())) {
    // End pointer.
    if (!HandleLValueArrayAdjustment(Info, E, Array,
                                     ArrayType->getElementType(),
                                     ArrayType->getSize().getZExtValue()))
      return false;
    Array.moveInto(Result.getStructField(1));
  } else if (Info.Ctx.hasSameType(Field->getType(), Info.Ctx.getSizeType()))
    // Length.
    Result.getStructField(1) = APValue(APSInt(ArrayType->getSize()));
  else
    return Error(E);

  if (++Field != Record->field_end())
    return Error(E);

  return true;
}

bool RecordExprEvaluator::VisitLambdaExpr(const LambdaExpr *E) {
  const CXXRecordDecl *ClosureClass = E->getLambdaClass();
  if (ClosureClass->isInvalidDecl())
    return false;

  const size_t NumFields =
      std::distance(ClosureClass->field_begin(), ClosureClass->field_end());

  assert(NumFields == (size_t)std::distance(E->capture_init_begin(),
                                            E->capture_init_end()) &&
         "The number of lambda capture initializers should equal the number of "
         "fields within the closure type");

  Result = APValue(APValue::UninitStruct(), /*NumBases*/0, NumFields);
  // Iterate through all the lambda's closure object's fields and initialize
  // them.
  auto *CaptureInitIt = E->capture_init_begin();
  const LambdaCapture *CaptureIt = ClosureClass->captures_begin();
  bool Success = true;
  for (const auto *Field : ClosureClass->fields()) {
    assert(CaptureInitIt != E->capture_init_end());
    // Get the initializer for this field
    Expr *const CurFieldInit = *CaptureInitIt++;

    // If there is no initializer, either this is a VLA or an error has
    // occurred.
    if (!CurFieldInit)
      return Error(E);

    APValue &FieldVal = Result.getStructField(Field->getFieldIndex());
    if (!EvaluateInPlace(FieldVal, Info, This, CurFieldInit)) {
      if (!Info.keepEvaluatingAfterFailure())
        return false;
      Success = false;
    }
    ++CaptureIt;
  }
  return Success;
}

static bool EvaluateRecord(const Expr *E, const LValue &This,
                           APValue &Result, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isRecordType() &&
         "can't evaluate expression as a record rvalue");
  return RecordExprEvaluator(Info, This, Result).Visit(E);
}

//===----------------------------------------------------------------------===//
// Temporary Evaluation
//
// Temporaries are represented in the AST as rvalues, but generally behave like
// lvalues. The full-object of which the temporary is a subobject is implicitly
// materialized so that a reference can bind to it.
//===----------------------------------------------------------------------===//
namespace {
class TemporaryExprEvaluator
  : public LValueExprEvaluatorBase<TemporaryExprEvaluator> {
public:
  TemporaryExprEvaluator(EvalInfo &Info, LValue &Result) :
    LValueExprEvaluatorBaseTy(Info, Result, false) {}

  /// Visit an expression which constructs the value of this temporary.
  bool VisitConstructExpr(const Expr *E) {
    APValue &Value =
        Info.CurrentCall->createTemporary(E, E->getType(), false, Result);
    return EvaluateInPlace(Value, Info, Result, E);
  }

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      return LValueExprEvaluatorBaseTy::VisitCastExpr(E);

    case CK_ConstructorConversion:
      return VisitConstructExpr(E->getSubExpr());
    }
  }
  bool VisitInitListExpr(const InitListExpr *E) {
    return VisitConstructExpr(E);
  }
  bool VisitCXXConstructExpr(const CXXConstructExpr *E) {
    return VisitConstructExpr(E);
  }
  bool VisitCallExpr(const CallExpr *E) {
    return VisitConstructExpr(E);
  }
  bool VisitCXXStdInitializerListExpr(const CXXStdInitializerListExpr *E) {
    return VisitConstructExpr(E);
  }
  bool VisitLambdaExpr(const LambdaExpr *E) {
    return VisitConstructExpr(E);
  }
};
} // end anonymous namespace

/// Evaluate an expression of record type as a temporary.
static bool EvaluateTemporary(const Expr *E, LValue &Result, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isRecordType());
  return TemporaryExprEvaluator(Info, Result).Visit(E);
}

//===----------------------------------------------------------------------===//
// Vector Evaluation
//===----------------------------------------------------------------------===//

namespace {
  class VectorExprEvaluator
  : public ExprEvaluatorBase<VectorExprEvaluator> {
    APValue &Result;
  public:

    VectorExprEvaluator(EvalInfo &info, APValue &Result)
      : ExprEvaluatorBaseTy(info), Result(Result) {}

    bool Success(ArrayRef<APValue> V, const Expr *E) {
      assert(V.size() == E->getType()->castAs<VectorType>()->getNumElements());
      // FIXME: remove this APValue copy.
      Result = APValue(V.data(), V.size());
      return true;
    }
    bool Success(const APValue &V, const Expr *E) {
      assert(V.isVector());
      Result = V;
      return true;
    }
    bool ZeroInitialization(const Expr *E);

    bool VisitUnaryReal(const UnaryOperator *E)
      { return Visit(E->getSubExpr()); }
    bool VisitCastExpr(const CastExpr* E);
    bool VisitInitListExpr(const InitListExpr *E);
    bool VisitUnaryImag(const UnaryOperator *E);
    // FIXME: Missing: unary -, unary ~, binary add/sub/mul/div,
    //                 binary comparisons, binary and/or/xor,
    //                 conditional operator (for GNU conditional select),
    //                 shufflevector, ExtVectorElementExpr
  };
} // end anonymous namespace

static bool EvaluateVector(const Expr* E, APValue& Result, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isVectorType() &&"not a vector rvalue");
  return VectorExprEvaluator(Info, Result).Visit(E);
}

bool VectorExprEvaluator::VisitCastExpr(const CastExpr *E) {
  const VectorType *VTy = E->getType()->castAs<VectorType>();
  unsigned NElts = VTy->getNumElements();

  const Expr *SE = E->getSubExpr();
  QualType SETy = SE->getType();

  switch (E->getCastKind()) {
  case CK_VectorSplat: {
    APValue Val = APValue();
    if (SETy->isIntegerType()) {
      APSInt IntResult;
      if (!EvaluateInteger(SE, IntResult, Info))
        return false;
      Val = APValue(std::move(IntResult));
    } else if (SETy->isRealFloatingType()) {
      APFloat FloatResult(0.0);
      if (!EvaluateFloat(SE, FloatResult, Info))
        return false;
      Val = APValue(std::move(FloatResult));
    } else {
      return Error(E);
    }

    // Splat and create vector APValue.
    SmallVector<APValue, 4> Elts(NElts, Val);
    return Success(Elts, E);
  }
  case CK_BitCast: {
    // Evaluate the operand into an APInt we can extract from.
    llvm::APInt SValInt;
    if (!EvalAndBitcastToAPInt(Info, SE, SValInt))
      return false;
    // Extract the elements
    QualType EltTy = VTy->getElementType();
    unsigned EltSize = Info.Ctx.getTypeSize(EltTy);
    bool BigEndian = Info.Ctx.getTargetInfo().isBigEndian();
    SmallVector<APValue, 4> Elts;
    if (EltTy->isRealFloatingType()) {
      const llvm::fltSemantics &Sem = Info.Ctx.getFloatTypeSemantics(EltTy);
      unsigned FloatEltSize = EltSize;
      if (&Sem == &APFloat::x87DoubleExtended())
        FloatEltSize = 80;
      for (unsigned i = 0; i < NElts; i++) {
        llvm::APInt Elt;
        if (BigEndian)
          Elt = SValInt.rotl(i*EltSize+FloatEltSize).trunc(FloatEltSize);
        else
          Elt = SValInt.rotr(i*EltSize).trunc(FloatEltSize);
        Elts.push_back(APValue(APFloat(Sem, Elt)));
      }
    } else if (EltTy->isIntegerType()) {
      for (unsigned i = 0; i < NElts; i++) {
        llvm::APInt Elt;
        if (BigEndian)
          Elt = SValInt.rotl(i*EltSize+EltSize).zextOrTrunc(EltSize);
        else
          Elt = SValInt.rotr(i*EltSize).zextOrTrunc(EltSize);
        Elts.push_back(APValue(APSInt(Elt, EltTy->isSignedIntegerType())));
      }
    } else {
      return Error(E);
    }
    return Success(Elts, E);
  }
  default:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);
  }
}

bool
VectorExprEvaluator::VisitInitListExpr(const InitListExpr *E) {
  const VectorType *VT = E->getType()->castAs<VectorType>();
  unsigned NumInits = E->getNumInits();
  unsigned NumElements = VT->getNumElements();

  QualType EltTy = VT->getElementType();
  SmallVector<APValue, 4> Elements;

  // The number of initializers can be less than the number of
  // vector elements. For OpenCL, this can be due to nested vector
  // initialization. For GCC compatibility, missing trailing elements
  // should be initialized with zeroes.
  unsigned CountInits = 0, CountElts = 0;
  while (CountElts < NumElements) {
    // Handle nested vector initialization.
    if (CountInits < NumInits
        && E->getInit(CountInits)->getType()->isVectorType()) {
      APValue v;
      if (!EvaluateVector(E->getInit(CountInits), v, Info))
        return Error(E);
      unsigned vlen = v.getVectorLength();
      for (unsigned j = 0; j < vlen; j++)
        Elements.push_back(v.getVectorElt(j));
      CountElts += vlen;
    } else if (EltTy->isIntegerType()) {
      llvm::APSInt sInt(32);
      if (CountInits < NumInits) {
        if (!EvaluateInteger(E->getInit(CountInits), sInt, Info))
          return false;
      } else // trailing integer zero.
        sInt = Info.Ctx.MakeIntValue(0, EltTy);
      Elements.push_back(APValue(sInt));
      CountElts++;
    } else {
      llvm::APFloat f(0.0);
      if (CountInits < NumInits) {
        if (!EvaluateFloat(E->getInit(CountInits), f, Info))
          return false;
      } else // trailing float zero.
        f = APFloat::getZero(Info.Ctx.getFloatTypeSemantics(EltTy));
      Elements.push_back(APValue(f));
      CountElts++;
    }
    CountInits++;
  }
  return Success(Elements, E);
}

bool
VectorExprEvaluator::ZeroInitialization(const Expr *E) {
  const auto *VT = E->getType()->castAs<VectorType>();
  QualType EltTy = VT->getElementType();
  APValue ZeroElement;
  if (EltTy->isIntegerType())
    ZeroElement = APValue(Info.Ctx.MakeIntValue(0, EltTy));
  else
    ZeroElement =
        APValue(APFloat::getZero(Info.Ctx.getFloatTypeSemantics(EltTy)));

  SmallVector<APValue, 4> Elements(VT->getNumElements(), ZeroElement);
  return Success(Elements, E);
}

bool VectorExprEvaluator::VisitUnaryImag(const UnaryOperator *E) {
  VisitIgnoredValue(E->getSubExpr());
  return ZeroInitialization(E);
}

//===----------------------------------------------------------------------===//
// Array Evaluation
//===----------------------------------------------------------------------===//

namespace {
  class ArrayExprEvaluator
  : public ExprEvaluatorBase<ArrayExprEvaluator> {
    const LValue &This;
    APValue &Result;
  public:

    ArrayExprEvaluator(EvalInfo &Info, const LValue &This, APValue &Result)
      : ExprEvaluatorBaseTy(Info), This(This), Result(Result) {}

    bool Success(const APValue &V, const Expr *E) {
      assert(V.isArray() && "expected array");
      Result = V;
      return true;
    }

    bool ZeroInitialization(const Expr *E) {
      const ConstantArrayType *CAT =
          Info.Ctx.getAsConstantArrayType(E->getType());
      if (!CAT)
        return Error(E);

      Result = APValue(APValue::UninitArray(), 0,
                       CAT->getSize().getZExtValue());
      if (!Result.hasArrayFiller()) return true;

      // Zero-initialize all elements.
      LValue Subobject = This;
      Subobject.addArray(Info, E, CAT);
      ImplicitValueInitExpr VIE(CAT->getElementType());
      return EvaluateInPlace(Result.getArrayFiller(), Info, Subobject, &VIE);
    }

    bool VisitCallExpr(const CallExpr *E) {
      return handleCallExpr(E, Result, &This);
    }
    bool VisitInitListExpr(const InitListExpr *E,
                           QualType AllocType = QualType());
    bool VisitArrayInitLoopExpr(const ArrayInitLoopExpr *E);
    bool VisitCXXConstructExpr(const CXXConstructExpr *E);
    bool VisitCXXConstructExpr(const CXXConstructExpr *E,
                               const LValue &Subobject,
                               APValue *Value, QualType Type);
    bool VisitStringLiteral(const StringLiteral *E,
                            QualType AllocType = QualType()) {
      expandStringLiteral(Info, E, Result, AllocType);
      return true;
    }
  };
} // end anonymous namespace

static bool EvaluateArray(const Expr *E, const LValue &This,
                          APValue &Result, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isArrayType() && "not an array rvalue");
  return ArrayExprEvaluator(Info, This, Result).Visit(E);
}

static bool EvaluateArrayNewInitList(EvalInfo &Info, LValue &This,
                                     APValue &Result, const InitListExpr *ILE,
                                     QualType AllocType) {
  assert(ILE->isRValue() && ILE->getType()->isArrayType() &&
         "not an array rvalue");
  return ArrayExprEvaluator(Info, This, Result)
      .VisitInitListExpr(ILE, AllocType);
}

static bool EvaluateArrayNewConstructExpr(EvalInfo &Info, LValue &This,
                                          APValue &Result,
                                          const CXXConstructExpr *CCE,
                                          QualType AllocType) {
  assert(CCE->isRValue() && CCE->getType()->isArrayType() &&
         "not an array rvalue");
  return ArrayExprEvaluator(Info, This, Result)
      .VisitCXXConstructExpr(CCE, This, &Result, AllocType);
}

// Return true iff the given array filler may depend on the element index.
static bool MaybeElementDependentArrayFiller(const Expr *FillerExpr) {
  // For now, just whitelist non-class value-initialization and initialization
  // lists comprised of them.
  if (isa<ImplicitValueInitExpr>(FillerExpr))
    return false;
  if (const InitListExpr *ILE = dyn_cast<InitListExpr>(FillerExpr)) {
    for (unsigned I = 0, E = ILE->getNumInits(); I != E; ++I) {
      if (MaybeElementDependentArrayFiller(ILE->getInit(I)))
        return true;
    }
    return false;
  }
  return true;
}

bool ArrayExprEvaluator::VisitInitListExpr(const InitListExpr *E,
                                           QualType AllocType) {
  const ConstantArrayType *CAT = Info.Ctx.getAsConstantArrayType(
      AllocType.isNull() ? E->getType() : AllocType);
  if (!CAT)
    return Error(E);

  // C++11 [dcl.init.string]p1: A char array [...] can be initialized by [...]
  // an appropriately-typed string literal enclosed in braces.
  if (E->isStringLiteralInit()) {
    auto *SL = dyn_cast<StringLiteral>(E->getInit(0)->IgnoreParens());
    // FIXME: Support ObjCEncodeExpr here once we support it in
    // ArrayExprEvaluator generally.
    if (!SL)
      return Error(E);
    return VisitStringLiteral(SL, AllocType);
  }

  bool Success = true;

  assert((!Result.isArray() || Result.getArrayInitializedElts() == 0) &&
         "zero-initialized array shouldn't have any initialized elts");
  APValue Filler;
  if (Result.isArray() && Result.hasArrayFiller())
    Filler = Result.getArrayFiller();

  unsigned NumEltsToInit = E->getNumInits();
  unsigned NumElts = CAT->getSize().getZExtValue();
  const Expr *FillerExpr = E->hasArrayFiller() ? E->getArrayFiller() : nullptr;

  // If the initializer might depend on the array index, run it for each
  // array element.
  if (NumEltsToInit != NumElts && MaybeElementDependentArrayFiller(FillerExpr))
    NumEltsToInit = NumElts;

  LLVM_DEBUG(llvm::dbgs() << "The number of elements to initialize: "
                          << NumEltsToInit << ".\n");

  Result = APValue(APValue::UninitArray(), NumEltsToInit, NumElts);

  // If the array was previously zero-initialized, preserve the
  // zero-initialized values.
  if (Filler.hasValue()) {
    for (unsigned I = 0, E = Result.getArrayInitializedElts(); I != E; ++I)
      Result.getArrayInitializedElt(I) = Filler;
    if (Result.hasArrayFiller())
      Result.getArrayFiller() = Filler;
  }

  LValue Subobject = This;
  Subobject.addArray(Info, E, CAT);
  for (unsigned Index = 0; Index != NumEltsToInit; ++Index) {
    const Expr *Init =
        Index < E->getNumInits() ? E->getInit(Index) : FillerExpr;
    if (!EvaluateInPlace(Result.getArrayInitializedElt(Index),
                         Info, Subobject, Init) ||
        !HandleLValueArrayAdjustment(Info, Init, Subobject,
                                     CAT->getElementType(), 1)) {
      if (!Info.noteFailure())
        return false;
      Success = false;
    }
  }

  if (!Result.hasArrayFiller())
    return Success;

  // If we get here, we have a trivial filler, which we can just evaluate
  // once and splat over the rest of the array elements.
  assert(FillerExpr && "no array filler for incomplete init list");
  return EvaluateInPlace(Result.getArrayFiller(), Info, Subobject,
                         FillerExpr) && Success;
}

bool ArrayExprEvaluator::VisitArrayInitLoopExpr(const ArrayInitLoopExpr *E) {
  LValue CommonLV;
  if (E->getCommonExpr() &&
      !Evaluate(Info.CurrentCall->createTemporary(
                    E->getCommonExpr(),
                    getStorageType(Info.Ctx, E->getCommonExpr()), false,
                    CommonLV),
                Info, E->getCommonExpr()->getSourceExpr()))
    return false;

  auto *CAT = cast<ConstantArrayType>(E->getType()->castAsArrayTypeUnsafe());

  uint64_t Elements = CAT->getSize().getZExtValue();
  Result = APValue(APValue::UninitArray(), Elements, Elements);

  LValue Subobject = This;
  Subobject.addArray(Info, E, CAT);

  bool Success = true;
  for (EvalInfo::ArrayInitLoopIndex Index(Info); Index != Elements; ++Index) {
    if (!EvaluateInPlace(Result.getArrayInitializedElt(Index),
                         Info, Subobject, E->getSubExpr()) ||
        !HandleLValueArrayAdjustment(Info, E, Subobject,
                                     CAT->getElementType(), 1)) {
      if (!Info.noteFailure())
        return false;
      Success = false;
    }
  }

  return Success;
}

bool ArrayExprEvaluator::VisitCXXConstructExpr(const CXXConstructExpr *E) {
  return VisitCXXConstructExpr(E, This, &Result, E->getType());
}

bool ArrayExprEvaluator::VisitCXXConstructExpr(const CXXConstructExpr *E,
                                               const LValue &Subobject,
                                               APValue *Value,
                                               QualType Type) {
  bool HadZeroInit = Value->hasValue();

  if (const ConstantArrayType *CAT = Info.Ctx.getAsConstantArrayType(Type)) {
    unsigned N = CAT->getSize().getZExtValue();

    // Preserve the array filler if we had prior zero-initialization.
    APValue Filler =
      HadZeroInit && Value->hasArrayFiller() ? Value->getArrayFiller()
                                             : APValue();

    *Value = APValue(APValue::UninitArray(), N, N);

    if (HadZeroInit)
      for (unsigned I = 0; I != N; ++I)
        Value->getArrayInitializedElt(I) = Filler;

    // Initialize the elements.
    LValue ArrayElt = Subobject;
    ArrayElt.addArray(Info, E, CAT);
    for (unsigned I = 0; I != N; ++I)
      if (!VisitCXXConstructExpr(E, ArrayElt, &Value->getArrayInitializedElt(I),
                                 CAT->getElementType()) ||
          !HandleLValueArrayAdjustment(Info, E, ArrayElt,
                                       CAT->getElementType(), 1))
        return false;

    return true;
  }

  if (!Type->isRecordType())
    return Error(E);

  return RecordExprEvaluator(Info, Subobject, *Value)
             .VisitCXXConstructExpr(E, Type);
}

//===----------------------------------------------------------------------===//
// Integer Evaluation
//
// As a GNU extension, we support casting pointers to sufficiently-wide integer
// types and back in constant folding. Integer values are thus represented
// either as an integer-valued APValue, or as an lvalue-valued APValue.
//===----------------------------------------------------------------------===//

namespace {
class IntExprEvaluator
        : public ExprEvaluatorBase<IntExprEvaluator> {
  APValue &Result;
public:
  IntExprEvaluator(EvalInfo &info, APValue &result)
      : ExprEvaluatorBaseTy(info), Result(result) {}

  bool Success(const llvm::APSInt &SI, const Expr *E, APValue &Result) {
    assert(E->getType()->isIntegralOrEnumerationType() &&
           "Invalid evaluation result.");
    assert(SI.isSigned() == E->getType()->isSignedIntegerOrEnumerationType() &&
           "Invalid evaluation result.");
    assert(SI.getBitWidth() == Info.Ctx.getIntWidth(E->getType()) &&
           "Invalid evaluation result.");
    Result = APValue(SI);
    return true;
  }
  bool Success(const llvm::APSInt &SI, const Expr *E) {
    return Success(SI, E, Result);
  }

  bool Success(const llvm::APInt &I, const Expr *E, APValue &Result) {
    assert(E->getType()->isIntegralOrEnumerationType() &&
           "Invalid evaluation result.");
    assert(I.getBitWidth() == Info.Ctx.getIntWidth(E->getType()) &&
           "Invalid evaluation result.");
    Result = APValue(APSInt(I));
    Result.getInt().setIsUnsigned(
                            E->getType()->isUnsignedIntegerOrEnumerationType());
    return true;
  }
  bool Success(const llvm::APInt &I, const Expr *E) {
    return Success(I, E, Result);
  }

  bool Success(uint64_t Value, const Expr *E, APValue &Result) {
    assert(E->getType()->isIntegralOrEnumerationType() &&
           "Invalid evaluation result.");
    Result = APValue(Info.Ctx.MakeIntValue(Value, E->getType()));
    return true;
  }
  bool Success(uint64_t Value, const Expr *E) {
    return Success(Value, E, Result);
  }

  bool Success(CharUnits Size, const Expr *E) {
    return Success(Size.getQuantity(), E);
  }

  bool Success(const APValue &V, const Expr *E) {
    if (V.isLValue() || V.isAddrLabelDiff() || V.isIndeterminate()) {
      Result = V;
      return true;
    }
    return Success(V.getInt(), E);
  }

  bool ZeroInitialization(const Expr *E) { return Success(0, E); }

  //===--------------------------------------------------------------------===//
  //                            Visitor Methods
  //===--------------------------------------------------------------------===//

  bool VisitConstantExpr(const ConstantExpr *E);

  bool VisitIntegerLiteral(const IntegerLiteral *E) {
    return Success(E->getValue(), E);
  }
  bool VisitCharacterLiteral(const CharacterLiteral *E) {
    return Success(E->getValue(), E);
  }

  bool CheckReferencedDecl(const Expr *E, const Decl *D);
  bool VisitDeclRefExpr(const DeclRefExpr *E) {
    if (CheckReferencedDecl(E, E->getDecl()))
      return true;

    return ExprEvaluatorBaseTy::VisitDeclRefExpr(E);
  }
  bool VisitMemberExpr(const MemberExpr *E) {
    if (CheckReferencedDecl(E, E->getMemberDecl())) {
      VisitIgnoredBaseExpression(E->getBase());
      return true;
    }

    return ExprEvaluatorBaseTy::VisitMemberExpr(E);
  }

  bool VisitCallExpr(const CallExpr *E);
  bool VisitBuiltinCallExpr(const CallExpr *E, unsigned BuiltinOp);
  bool VisitBinaryOperator(const BinaryOperator *E);
  bool VisitOffsetOfExpr(const OffsetOfExpr *E);
  bool VisitUnaryOperator(const UnaryOperator *E);

  bool VisitCastExpr(const CastExpr* E);
  bool VisitUnaryExprOrTypeTraitExpr(const UnaryExprOrTypeTraitExpr *E);

  bool VisitCXXBoolLiteralExpr(const CXXBoolLiteralExpr *E) {
    return Success(E->getValue(), E);
  }

  bool VisitObjCBoolLiteralExpr(const ObjCBoolLiteralExpr *E) {
    return Success(E->getValue(), E);
  }

  bool VisitArrayInitIndexExpr(const ArrayInitIndexExpr *E) {
    if (Info.ArrayInitIndex == uint64_t(-1)) {
      // We were asked to evaluate this subexpression independent of the
      // enclosing ArrayInitLoopExpr. We can't do that.
      Info.FFDiag(E);
      return false;
    }
    return Success(Info.ArrayInitIndex, E);
  }

  // Note, GNU defines __null as an integer, not a pointer.
  bool VisitGNUNullExpr(const GNUNullExpr *E) {
    return ZeroInitialization(E);
  }

  bool VisitTypeTraitExpr(const TypeTraitExpr *E) {
    return Success(E->getValue(), E);
  }

  bool VisitArrayTypeTraitExpr(const ArrayTypeTraitExpr *E) {
    return Success(E->getValue(), E);
  }

  bool VisitExpressionTraitExpr(const ExpressionTraitExpr *E) {
    return Success(E->getValue(), E);
  }

  bool VisitUnaryReal(const UnaryOperator *E);
  bool VisitUnaryImag(const UnaryOperator *E);

  bool VisitCXXNoexceptExpr(const CXXNoexceptExpr *E);
  bool VisitSizeOfPackExpr(const SizeOfPackExpr *E);
  bool VisitSourceLocExpr(const SourceLocExpr *E);
  bool VisitConceptSpecializationExpr(const ConceptSpecializationExpr *E);
  bool VisitRequiresExpr(const RequiresExpr *E);
  // FIXME: Missing: array subscript of vector, member of vector
};

class FixedPointExprEvaluator
    : public ExprEvaluatorBase<FixedPointExprEvaluator> {
  APValue &Result;

 public:
  FixedPointExprEvaluator(EvalInfo &info, APValue &result)
      : ExprEvaluatorBaseTy(info), Result(result) {}

  bool Success(const llvm::APInt &I, const Expr *E) {
    return Success(
        APFixedPoint(I, Info.Ctx.getFixedPointSemantics(E->getType())), E);
  }

  bool Success(uint64_t Value, const Expr *E) {
    return Success(
        APFixedPoint(Value, Info.Ctx.getFixedPointSemantics(E->getType())), E);
  }

  bool Success(const APValue &V, const Expr *E) {
    return Success(V.getFixedPoint(), E);
  }

  bool Success(const APFixedPoint &V, const Expr *E) {
    assert(E->getType()->isFixedPointType() && "Invalid evaluation result.");
    assert(V.getWidth() == Info.Ctx.getIntWidth(E->getType()) &&
           "Invalid evaluation result.");
    Result = APValue(V);
    return true;
  }

  //===--------------------------------------------------------------------===//
  //                            Visitor Methods
  //===--------------------------------------------------------------------===//

  bool VisitFixedPointLiteral(const FixedPointLiteral *E) {
    return Success(E->getValue(), E);
  }

  bool VisitCastExpr(const CastExpr *E);
  bool VisitUnaryOperator(const UnaryOperator *E);
  bool VisitBinaryOperator(const BinaryOperator *E);
};
} // end anonymous namespace

/// EvaluateIntegerOrLValue - Evaluate an rvalue integral-typed expression, and
/// produce either the integer value or a pointer.
///
/// GCC has a heinous extension which folds casts between pointer types and
/// pointer-sized integral types. We support this by allowing the evaluation of
/// an integer rvalue to produce a pointer (represented as an lvalue) instead.
/// Some simple arithmetic on such values is supported (they are treated much
/// like char*).
static bool EvaluateIntegerOrLValue(const Expr *E, APValue &Result,
                                    EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isIntegralOrEnumerationType());
  return IntExprEvaluator(Info, Result).Visit(E);
}

static bool EvaluateInteger(const Expr *E, APSInt &Result, EvalInfo &Info) {
  APValue Val;
  if (!EvaluateIntegerOrLValue(E, Val, Info))
    return false;
  if (!Val.isInt()) {
    // FIXME: It would be better to produce the diagnostic for casting
    //        a pointer to an integer.
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }
  Result = Val.getInt();
  return true;
}

bool IntExprEvaluator::VisitSourceLocExpr(const SourceLocExpr *E) {
  APValue Evaluated = E->EvaluateInContext(
      Info.Ctx, Info.CurrentCall->CurSourceLocExprScope.getDefaultExpr());
  return Success(Evaluated, E);
}

static bool EvaluateFixedPoint(const Expr *E, APFixedPoint &Result,
                               EvalInfo &Info) {
  if (E->getType()->isFixedPointType()) {
    APValue Val;
    if (!FixedPointExprEvaluator(Info, Val).Visit(E))
      return false;
    if (!Val.isFixedPoint())
      return false;

    Result = Val.getFixedPoint();
    return true;
  }
  return false;
}

static bool EvaluateFixedPointOrInteger(const Expr *E, APFixedPoint &Result,
                                        EvalInfo &Info) {
  if (E->getType()->isIntegerType()) {
    auto FXSema = Info.Ctx.getFixedPointSemantics(E->getType());
    APSInt Val;
    if (!EvaluateInteger(E, Val, Info))
      return false;
    Result = APFixedPoint(Val, FXSema);
    return true;
  } else if (E->getType()->isFixedPointType()) {
    return EvaluateFixedPoint(E, Result, Info);
  }
  return false;
}

/// Check whether the given declaration can be directly converted to an integral
/// rvalue. If not, no diagnostic is produced; there are other things we can
/// try.
bool IntExprEvaluator::CheckReferencedDecl(const Expr* E, const Decl* D) {
  // Enums are integer constant exprs.
  if (const EnumConstantDecl *ECD = dyn_cast<EnumConstantDecl>(D)) {
    // Check for signedness/width mismatches between E type and ECD value.
    bool SameSign = (ECD->getInitVal().isSigned()
                     == E->getType()->isSignedIntegerOrEnumerationType());
    bool SameWidth = (ECD->getInitVal().getBitWidth()
                      == Info.Ctx.getIntWidth(E->getType()));
    if (SameSign && SameWidth)
      return Success(ECD->getInitVal(), E);
    else {
      // Get rid of mismatch (otherwise Success assertions will fail)
      // by computing a new value matching the type of E.
      llvm::APSInt Val = ECD->getInitVal();
      if (!SameSign)
        Val.setIsSigned(!ECD->getInitVal().isSigned());
      if (!SameWidth)
        Val = Val.extOrTrunc(Info.Ctx.getIntWidth(E->getType()));
      return Success(Val, E);
    }
  }
  return false;
}

/// Values returned by __builtin_classify_type, chosen to match the values
/// produced by GCC's builtin.
enum class GCCTypeClass {
  None = -1,
  Void = 0,
  Integer = 1,
  // GCC reserves 2 for character types, but instead classifies them as
  // integers.
  Enum = 3,
  Bool = 4,
  Pointer = 5,
  // GCC reserves 6 for references, but appears to never use it (because
  // expressions never have reference type, presumably).
  PointerToDataMember = 7,
  RealFloat = 8,
  Complex = 9,
  // GCC reserves 10 for functions, but does not use it since GCC version 6 due
  // to decay to pointer. (Prior to version 6 it was only used in C++ mode).
  // GCC claims to reserve 11 for pointers to member functions, but *actually*
  // uses 12 for that purpose, same as for a class or struct. Maybe it
  // internally implements a pointer to member as a struct?  Who knows.
  PointerToMemberFunction = 12, // Not a bug, see above.
  ClassOrStruct = 12,
  Union = 13,
  // GCC reserves 14 for arrays, but does not use it since GCC version 6 due to
  // decay to pointer. (Prior to version 6 it was only used in C++ mode).
  // GCC reserves 15 for strings, but actually uses 5 (pointer) for string
  // literals.
};

/// EvaluateBuiltinClassifyType - Evaluate __builtin_classify_type the same way
/// as GCC.
static GCCTypeClass
EvaluateBuiltinClassifyType(QualType T, const LangOptions &LangOpts) {
  assert(!T->isDependentType() && "unexpected dependent type");

  QualType CanTy = T.getCanonicalType();
  const BuiltinType *BT = dyn_cast<BuiltinType>(CanTy);

  switch (CanTy->getTypeClass()) {
#define TYPE(ID, BASE)
#define DEPENDENT_TYPE(ID, BASE) case Type::ID:
#define NON_CANONICAL_TYPE(ID, BASE) case Type::ID:
#define NON_CANONICAL_UNLESS_DEPENDENT_TYPE(ID, BASE) case Type::ID:
#include "clang/AST/TypeNodes.inc"
  case Type::Auto:
  case Type::DeducedTemplateSpecialization:
      llvm_unreachable("unexpected non-canonical or dependent type");

  case Type::Builtin:
    switch (BT->getKind()) {
#define BUILTIN_TYPE(ID, SINGLETON_ID)
#define SIGNED_TYPE(ID, SINGLETON_ID) \
    case BuiltinType::ID: return GCCTypeClass::Integer;
#define FLOATING_TYPE(ID, SINGLETON_ID) \
    case BuiltinType::ID: return GCCTypeClass::RealFloat;
#define PLACEHOLDER_TYPE(ID, SINGLETON_ID) \
    case BuiltinType::ID: break;
#include "clang/AST/BuiltinTypes.def"
    case BuiltinType::Void:
      return GCCTypeClass::Void;

    case BuiltinType::Bool:
      return GCCTypeClass::Bool;

    case BuiltinType::Char_U:
    case BuiltinType::UChar:
    case BuiltinType::WChar_U:
    case BuiltinType::Char8:
    case BuiltinType::Char16:
    case BuiltinType::Char32:
    case BuiltinType::UShort:
    case BuiltinType::UInt:
    case BuiltinType::ULong:
    case BuiltinType::ULongLong:
    case BuiltinType::UInt128:
      return GCCTypeClass::Integer;

    case BuiltinType::UShortAccum:
    case BuiltinType::UAccum:
    case BuiltinType::ULongAccum:
    case BuiltinType::UShortFract:
    case BuiltinType::UFract:
    case BuiltinType::ULongFract:
    case BuiltinType::SatUShortAccum:
    case BuiltinType::SatUAccum:
    case BuiltinType::SatULongAccum:
    case BuiltinType::SatUShortFract:
    case BuiltinType::SatUFract:
    case BuiltinType::SatULongFract:
      return GCCTypeClass::None;

    case BuiltinType::NullPtr:

    case BuiltinType::ObjCId:
    case BuiltinType::ObjCClass:
    case BuiltinType::ObjCSel:
#define IMAGE_TYPE(ImgType, Id, SingletonId, Access, Suffix) \
    case BuiltinType::Id:
#include "clang/Basic/OpenCLImageTypes.def"
#define EXT_OPAQUE_TYPE(ExtType, Id, Ext) \
    case BuiltinType::Id:
#include "clang/Basic/OpenCLExtensionTypes.def"
    case BuiltinType::OCLSampler:
    case BuiltinType::OCLEvent:
    case BuiltinType::OCLClkEvent:
    case BuiltinType::OCLQueue:
    case BuiltinType::OCLReserveID:
#define SVE_TYPE(Name, Id, SingletonId) \
    case BuiltinType::Id:
#include "clang/Basic/AArch64SVEACLETypes.def"
      return GCCTypeClass::None;

    case BuiltinType::Dependent:
      llvm_unreachable("unexpected dependent type");
    };
    llvm_unreachable("unexpected placeholder type");

  case Type::Enum:
    return LangOpts.CPlusPlus ? GCCTypeClass::Enum : GCCTypeClass::Integer;

  case Type::Pointer:
  case Type::ConstantArray:
  case Type::VariableArray:
  case Type::IncompleteArray:
  case Type::FunctionNoProto:
  case Type::FunctionProto:
    return GCCTypeClass::Pointer;

  case Type::MemberPointer:
    return CanTy->isMemberDataPointerType()
               ? GCCTypeClass::PointerToDataMember
               : GCCTypeClass::PointerToMemberFunction;

  case Type::Complex:
    return GCCTypeClass::Complex;

  case Type::Record:
    return CanTy->isUnionType() ? GCCTypeClass::Union
                                : GCCTypeClass::ClassOrStruct;

  case Type::Atomic:
    // GCC classifies _Atomic T the same as T.
    return EvaluateBuiltinClassifyType(
        CanTy->castAs<AtomicType>()->getValueType(), LangOpts);

  case Type::BlockPointer:
  case Type::Vector:
  case Type::ExtVector:
  case Type::ObjCObject:
  case Type::ObjCInterface:
  case Type::ObjCObjectPointer:
  case Type::Pipe:
    // GCC classifies vectors as None. We follow its lead and classify all
    // other types that don't fit into the regular classification the same way.
    return GCCTypeClass::None;

  case Type::LValueReference:
  case Type::RValueReference:
    llvm_unreachable("invalid type for expression");
  }

  llvm_unreachable("unexpected type class");
}

/// EvaluateBuiltinClassifyType - Evaluate __builtin_classify_type the same way
/// as GCC.
static GCCTypeClass
EvaluateBuiltinClassifyType(const CallExpr *E, const LangOptions &LangOpts) {
  // If no argument was supplied, default to None. This isn't
  // ideal, however it is what gcc does.
  if (E->getNumArgs() == 0)
    return GCCTypeClass::None;

  // FIXME: Bizarrely, GCC treats a call with more than one argument as not
  // being an ICE, but still folds it to a constant using the type of the first
  // argument.
  return EvaluateBuiltinClassifyType(E->getArg(0)->getType(), LangOpts);
}

/// EvaluateBuiltinConstantPForLValue - Determine the result of
/// __builtin_constant_p when applied to the given pointer.
///
/// A pointer is only "constant" if it is null (or a pointer cast to integer)
/// or it points to the first character of a string literal.
static bool EvaluateBuiltinConstantPForLValue(const APValue &LV) {
  APValue::LValueBase Base = LV.getLValueBase();
  if (Base.isNull()) {
    // A null base is acceptable.
    return true;
  } else if (const Expr *E = Base.dyn_cast<const Expr *>()) {
    if (!isa<StringLiteral>(E))
      return false;
    return LV.getLValueOffset().isZero();
  } else if (Base.is<TypeInfoLValue>()) {
    // Surprisingly, GCC considers __builtin_constant_p(&typeid(int)) to
    // evaluate to true.
    return true;
  } else {
    // Any other base is not constant enough for GCC.
    return false;
  }
}

/// EvaluateBuiltinConstantP - Evaluate __builtin_constant_p as similarly to
/// GCC as we can manage.
static bool EvaluateBuiltinConstantP(EvalInfo &Info, const Expr *Arg) {
  // This evaluation is not permitted to have side-effects, so evaluate it in
  // a speculative evaluation context.
  SpeculativeEvaluationRAII SpeculativeEval(Info);

  // Constant-folding is always enabled for the operand of __builtin_constant_p
  // (even when the enclosing evaluation context otherwise requires a strict
  // language-specific constant expression).
  FoldConstant Fold(Info, true);

  QualType ArgType = Arg->getType();

  // __builtin_constant_p always has one operand. The rules which gcc follows
  // are not precisely documented, but are as follows:
  //
  //  - If the operand is of integral, floating, complex or enumeration type,
  //    and can be folded to a known value of that type, it returns 1.
  //  - If the operand can be folded to a pointer to the first character
  //    of a string literal (or such a pointer cast to an integral type)
  //    or to a null pointer or an integer cast to a pointer, it returns 1.
  //
  // Otherwise, it returns 0.
  //
  // FIXME: GCC also intends to return 1 for literals of aggregate types, but
  // its support for this did not work prior to GCC 9 and is not yet well
  // understood.
  if (ArgType->isIntegralOrEnumerationType() || ArgType->isFloatingType() ||
      ArgType->isAnyComplexType() || ArgType->isPointerType() ||
      ArgType->isNullPtrType()) {
    APValue V;
    if (!::EvaluateAsRValue(Info, Arg, V)) {
      Fold.keepDiagnostics();
      return false;
    }

    // For a pointer (possibly cast to integer), there are special rules.
    if (V.getKind() == APValue::LValue)
      return EvaluateBuiltinConstantPForLValue(V);

    // Otherwise, any constant value is good enough.
    return V.hasValue();
  }

  // Anything else isn't considered to be sufficiently constant.
  return false;
}

/// Retrieves the "underlying object type" of the given expression,
/// as used by __builtin_object_size.
static QualType getObjectType(APValue::LValueBase B) {
  if (const ValueDecl *D = B.dyn_cast<const ValueDecl*>()) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(D))
      return VD->getType();
  } else if (const Expr *E = B.dyn_cast<const Expr*>()) {
    if (isa<CompoundLiteralExpr>(E))
      return E->getType();
  } else if (B.is<TypeInfoLValue>()) {
    return B.getTypeInfoType();
  } else if (B.is<DynamicAllocLValue>()) {
    return B.getDynamicAllocType();
  }

  return QualType();
}

/// A more selective version of E->IgnoreParenCasts for
/// tryEvaluateBuiltinObjectSize. This ignores some casts/parens that serve only
/// to change the type of E.
/// Ex. For E = `(short*)((char*)(&foo))`, returns `&foo`
///
/// Always returns an RValue with a pointer representation.
static const Expr *ignorePointerCastsAndParens(const Expr *E) {
  assert(E->isRValue() && E->getType()->hasPointerRepresentation());

  auto *NoParens = E->IgnoreParens();
  auto *Cast = dyn_cast<CastExpr>(NoParens);
  if (Cast == nullptr)
    return NoParens;

  // We only conservatively allow a few kinds of casts, because this code is
  // inherently a simple solution that seeks to support the common case.
  auto CastKind = Cast->getCastKind();
  if (CastKind != CK_NoOp && CastKind != CK_BitCast &&
      CastKind != CK_AddressSpaceConversion)
    return NoParens;

  auto *SubExpr = Cast->getSubExpr();
  if (!SubExpr->getType()->hasPointerRepresentation() || !SubExpr->isRValue())
    return NoParens;
  return ignorePointerCastsAndParens(SubExpr);
}

/// Checks to see if the given LValue's Designator is at the end of the LValue's
/// record layout. e.g.
///   struct { struct { int a, b; } fst, snd; } obj;
///   obj.fst   // no
///   obj.snd   // yes
///   obj.fst.a // no
///   obj.fst.b // no
///   obj.snd.a // no
///   obj.snd.b // yes
///
/// Please note: this function is specialized for how __builtin_object_size
/// views "objects".
///
/// If this encounters an invalid RecordDecl or otherwise cannot determine the
/// correct result, it will always return true.
static bool isDesignatorAtObjectEnd(const ASTContext &Ctx, const LValue &LVal) {
  assert(!LVal.Designator.Invalid);

  auto IsLastOrInvalidFieldDecl = [&Ctx](const FieldDecl *FD, bool &Invalid) {
    const RecordDecl *Parent = FD->getParent();
    Invalid = Parent->isInvalidDecl();
    if (Invalid || Parent->isUnion())
      return true;
    const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(Parent);
    return FD->getFieldIndex() + 1 == Layout.getFieldCount();
  };

  auto &Base = LVal.getLValueBase();
  if (auto *ME = dyn_cast_or_null<MemberExpr>(Base.dyn_cast<const Expr *>())) {
    if (auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      bool Invalid;
      if (!IsLastOrInvalidFieldDecl(FD, Invalid))
        return Invalid;
    } else if (auto *IFD = dyn_cast<IndirectFieldDecl>(ME->getMemberDecl())) {
      for (auto *FD : IFD->chain()) {
        bool Invalid;
        if (!IsLastOrInvalidFieldDecl(cast<FieldDecl>(FD), Invalid))
          return Invalid;
      }
    }
  }

  unsigned I = 0;
  QualType BaseType = getType(Base);
  if (LVal.Designator.FirstEntryIsAnUnsizedArray) {
    // If we don't know the array bound, conservatively assume we're looking at
    // the final array element.
    ++I;
    if (BaseType->isIncompleteArrayType())
      BaseType = Ctx.getAsArrayType(BaseType)->getElementType();
    else
      BaseType = BaseType->castAs<PointerType>()->getPointeeType();
  }

  for (unsigned E = LVal.Designator.Entries.size(); I != E; ++I) {
    const auto &Entry = LVal.Designator.Entries[I];
    if (BaseType->isArrayType()) {
      // Because __builtin_object_size treats arrays as objects, we can ignore
      // the index iff this is the last array in the Designator.
      if (I + 1 == E)
        return true;
      const auto *CAT = cast<ConstantArrayType>(Ctx.getAsArrayType(BaseType));
      uint64_t Index = Entry.getAsArrayIndex();
      if (Index + 1 != CAT->getSize())
        return false;
      BaseType = CAT->getElementType();
    } else if (BaseType->isAnyComplexType()) {
      const auto *CT = BaseType->castAs<ComplexType>();
      uint64_t Index = Entry.getAsArrayIndex();
      if (Index != 1)
        return false;
      BaseType = CT->getElementType();
    } else if (auto *FD = getAsField(Entry)) {
      bool Invalid;
      if (!IsLastOrInvalidFieldDecl(FD, Invalid))
        return Invalid;
      BaseType = FD->getType();
    } else {
      assert(getAsBaseClass(Entry) && "Expecting cast to a base class");
      return false;
    }
  }
  return true;
}

/// Tests to see if the LValue has a user-specified designator (that isn't
/// necessarily valid). Note that this always returns 'true' if the LValue has
/// an unsized array as its first designator entry, because there's currently no
/// way to tell if the user typed *foo or foo[0].
static bool refersToCompleteObject(const LValue &LVal) {
  if (LVal.Designator.Invalid)
    return false;

  if (!LVal.Designator.Entries.empty())
    return LVal.Designator.isMostDerivedAnUnsizedArray();

  if (!LVal.InvalidBase)
    return true;

  // If `E` is a MemberExpr, then the first part of the designator is hiding in
  // the LValueBase.
  const auto *E = LVal.Base.dyn_cast<const Expr *>();
  return !E || !isa<MemberExpr>(E);
}

/// Attempts to detect a user writing into a piece of memory that's impossible
/// to figure out the size of by just using types.
static bool isUserWritingOffTheEnd(const ASTContext &Ctx, const LValue &LVal) {
  const SubobjectDesignator &Designator = LVal.Designator;
  // Notes:
  // - Users can only write off of the end when we have an invalid base. Invalid
  //   bases imply we don't know where the memory came from.
  // - We used to be a bit more aggressive here; we'd only be conservative if
  //   the array at the end was flexible, or if it had 0 or 1 elements. This
  //   broke some common standard library extensions (PR30346), but was
  //   otherwise seemingly fine. It may be useful to reintroduce this behavior
  //   with some sort of whitelist. OTOH, it seems that GCC is always
  //   conservative with the last element in structs (if it's an array), so our
  //   current behavior is more compatible than a whitelisting approach would
  //   be.
  return LVal.InvalidBase &&
         Designator.Entries.size() == Designator.MostDerivedPathLength &&
         Designator.MostDerivedIsArrayElement &&
         isDesignatorAtObjectEnd(Ctx, LVal);
}

/// Converts the given APInt to CharUnits, assuming the APInt is unsigned.
/// Fails if the conversion would cause loss of precision.
static bool convertUnsignedAPIntToCharUnits(const llvm::APInt &Int,
                                            CharUnits &Result) {
  auto CharUnitsMax = std::numeric_limits<CharUnits::QuantityType>::max();
  if (Int.ugt(CharUnitsMax))
    return false;
  Result = CharUnits::fromQuantity(Int.getZExtValue());
  return true;
}

/// Helper for tryEvaluateBuiltinObjectSize -- Given an LValue, this will
/// determine how many bytes exist from the beginning of the object to either
/// the end of the current subobject, or the end of the object itself, depending
/// on what the LValue looks like + the value of Type.
///
/// If this returns false, the value of Result is undefined.
static bool determineEndOffset(EvalInfo &Info, SourceLocation ExprLoc,
                               unsigned Type, const LValue &LVal,
                               CharUnits &EndOffset) {
  bool DetermineForCompleteObject = refersToCompleteObject(LVal);

  auto CheckedHandleSizeof = [&](QualType Ty, CharUnits &Result) {
    if (Ty.isNull() || Ty->isIncompleteType() || Ty->isFunctionType())
      return false;
    return HandleSizeof(Info, ExprLoc, Ty, Result);
  };

  // We want to evaluate the size of the entire object. This is a valid fallback
  // for when Type=1 and the designator is invalid, because we're asked for an
  // upper-bound.
  if (!(Type & 1) || LVal.Designator.Invalid || DetermineForCompleteObject) {
    // Type=3 wants a lower bound, so we can't fall back to this.
    if (Type == 3 && !DetermineForCompleteObject)
      return false;

    llvm::APInt APEndOffset;
    if (isBaseAnAllocSizeCall(LVal.getLValueBase()) &&
        getBytesReturnedByAllocSizeCall(Info.Ctx, LVal, APEndOffset))
      return convertUnsignedAPIntToCharUnits(APEndOffset, EndOffset);

    if (LVal.InvalidBase)
      return false;

    QualType BaseTy = getObjectType(LVal.getLValueBase());
    return CheckedHandleSizeof(BaseTy, EndOffset);
  }

  // We want to evaluate the size of a subobject.
  const SubobjectDesignator &Designator = LVal.Designator;

  // The following is a moderately common idiom in C:
  //
  // struct Foo { int a; char c[1]; };
  // struct Foo *F = (struct Foo *)malloc(sizeof(struct Foo) + strlen(Bar));
  // strcpy(&F->c[0], Bar);
  //
  // In order to not break too much legacy code, we need to support it.
  if (isUserWritingOffTheEnd(Info.Ctx, LVal)) {
    // If we can resolve this to an alloc_size call, we can hand that back,
    // because we know for certain how many bytes there are to write to.
    llvm::APInt APEndOffset;
    if (isBaseAnAllocSizeCall(LVal.getLValueBase()) &&
        getBytesReturnedByAllocSizeCall(Info.Ctx, LVal, APEndOffset))
      return convertUnsignedAPIntToCharUnits(APEndOffset, EndOffset);

    // If we cannot determine the size of the initial allocation, then we can't
    // given an accurate upper-bound. However, we are still able to give
    // conservative lower-bounds for Type=3.
    if (Type == 1)
      return false;
  }

  CharUnits BytesPerElem;
  if (!CheckedHandleSizeof(Designator.MostDerivedType, BytesPerElem))
    return false;

  // According to the GCC documentation, we want the size of the subobject
  // denoted by the pointer. But that's not quite right -- what we actually
  // want is the size of the immediately-enclosing array, if there is one.
  int64_t ElemsRemaining;
  if (Designator.MostDerivedIsArrayElement &&
      Designator.Entries.size() == Designator.MostDerivedPathLength) {
    uint64_t ArraySize = Designator.getMostDerivedArraySize();
    uint64_t ArrayIndex = Designator.Entries.back().getAsArrayIndex();
    ElemsRemaining = ArraySize <= ArrayIndex ? 0 : ArraySize - ArrayIndex;
  } else {
    ElemsRemaining = Designator.isOnePastTheEnd() ? 0 : 1;
  }

  EndOffset = LVal.getLValueOffset() + BytesPerElem * ElemsRemaining;
  return true;
}

/// Tries to evaluate the __builtin_object_size for @p E. If successful,
/// returns true and stores the result in @p Size.
///
/// If @p WasError is non-null, this will report whether the failure to evaluate
/// is to be treated as an Error in IntExprEvaluator.
static bool tryEvaluateBuiltinObjectSize(const Expr *E, unsigned Type,
                                         EvalInfo &Info, uint64_t &Size) {
  // Determine the denoted object.
  LValue LVal;
  {
    // The operand of __builtin_object_size is never evaluated for side-effects.
    // If there are any, but we can determine the pointed-to object anyway, then
    // ignore the side-effects.
    SpeculativeEvaluationRAII SpeculativeEval(Info);
    IgnoreSideEffectsRAII Fold(Info);

    if (E->isGLValue()) {
      // It's possible for us to be given GLValues if we're called via
      // Expr::tryEvaluateObjectSize.
      APValue RVal;
      if (!EvaluateAsRValue(Info, E, RVal))
        return false;
      LVal.setFrom(Info.Ctx, RVal);
    } else if (!EvaluatePointer(ignorePointerCastsAndParens(E), LVal, Info,
                                /*InvalidBaseOK=*/true))
      return false;
  }

  // If we point to before the start of the object, there are no accessible
  // bytes.
  if (LVal.getLValueOffset().isNegative()) {
    Size = 0;
    return true;
  }

  CharUnits EndOffset;
  if (!determineEndOffset(Info, E->getExprLoc(), Type, LVal, EndOffset))
    return false;

  // If we've fallen outside of the end offset, just pretend there's nothing to
  // write to/read from.
  if (EndOffset <= LVal.getLValueOffset())
    Size = 0;
  else
    Size = (EndOffset - LVal.getLValueOffset()).getQuantity();
  return true;
}

bool IntExprEvaluator::VisitConstantExpr(const ConstantExpr *E) {
  llvm::SaveAndRestore<bool> InConstantContext(Info.InConstantContext, true);
  if (E->getResultAPValueKind() != APValue::None)
    return Success(E->getAPValueResult(), E);
  return ExprEvaluatorBaseTy::VisitConstantExpr(E);
}

bool IntExprEvaluator::VisitCallExpr(const CallExpr *E) {
  if (unsigned BuiltinOp = E->getBuiltinCallee())
    return VisitBuiltinCallExpr(E, BuiltinOp);

  return ExprEvaluatorBaseTy::VisitCallExpr(E);
}

static bool getBuiltinAlignArguments(const CallExpr *E, EvalInfo &Info,
                                     APValue &Val, APSInt &Alignment) {
  QualType SrcTy = E->getArg(0)->getType();
  if (!getAlignmentArgument(E->getArg(1), SrcTy, Info, Alignment))
    return false;
  // Even though we are evaluating integer expressions we could get a pointer
  // argument for the __builtin_is_aligned() case.
  if (SrcTy->isPointerType()) {
    LValue Ptr;
    if (!EvaluatePointer(E->getArg(0), Ptr, Info))
      return false;
    Ptr.moveInto(Val);
  } else if (!SrcTy->isIntegralOrEnumerationType()) {
    Info.FFDiag(E->getArg(0));
    return false;
  } else {
    APSInt SrcInt;
    if (!EvaluateInteger(E->getArg(0), SrcInt, Info))
      return false;
    assert(SrcInt.getBitWidth() >= Alignment.getBitWidth() &&
           "Bit widths must be the same");
    Val = APValue(SrcInt);
  }
  assert(Val.hasValue());
  return true;
}

bool IntExprEvaluator::VisitBuiltinCallExpr(const CallExpr *E,
                                            unsigned BuiltinOp) {
  switch (unsigned BuiltinOp = E->getBuiltinCallee()) {
  default:
    return ExprEvaluatorBaseTy::VisitCallExpr(E);

  case Builtin::BI__builtin_dynamic_object_size:
  case Builtin::BI__builtin_object_size: {
    // The type was checked when we built the expression.
    unsigned Type =
        E->getArg(1)->EvaluateKnownConstInt(Info.Ctx).getZExtValue();
    assert(Type <= 3 && "unexpected type");

    uint64_t Size;
    if (tryEvaluateBuiltinObjectSize(E->getArg(0), Type, Info, Size))
      return Success(Size, E);

    if (E->getArg(0)->HasSideEffects(Info.Ctx))
      return Success((Type & 2) ? 0 : -1, E);

    // Expression had no side effects, but we couldn't statically determine the
    // size of the referenced object.
    switch (Info.EvalMode) {
    case EvalInfo::EM_ConstantExpression:
    case EvalInfo::EM_ConstantFold:
    case EvalInfo::EM_IgnoreSideEffects:
      // Leave it to IR generation.
      return Error(E);
    case EvalInfo::EM_ConstantExpressionUnevaluated:
      // Reduce it to a constant now.
      return Success((Type & 2) ? 0 : -1, E);
    }

    llvm_unreachable("unexpected EvalMode");
  }

  case Builtin::BI__builtin_os_log_format_buffer_size: {
    analyze_os_log::OSLogBufferLayout Layout;
    analyze_os_log::computeOSLogBufferLayout(Info.Ctx, E, Layout);
    return Success(Layout.size().getQuantity(), E);
  }

  case Builtin::BI__builtin_is_aligned: {
    APValue Src;
    APSInt Alignment;
    if (!getBuiltinAlignArguments(E, Info, Src, Alignment))
      return false;
    if (Src.isLValue()) {
      // If we evaluated a pointer, check the minimum known alignment.
      LValue Ptr;
      Ptr.setFrom(Info.Ctx, Src);
      CharUnits BaseAlignment = getBaseAlignment(Info, Ptr);
      CharUnits PtrAlign = BaseAlignment.alignmentAtOffset(Ptr.Offset);
      // We can return true if the known alignment at the computed offset is
      // greater than the requested alignment.
      assert(PtrAlign.isPowerOfTwo());
      assert(Alignment.isPowerOf2());
      if (PtrAlign.getQuantity() >= Alignment)
        return Success(1, E);
      // If the alignment is not known to be sufficient, some cases could still
      // be aligned at run time. However, if the requested alignment is less or
      // equal to the base alignment and the offset is not aligned, we know that
      // the run-time value can never be aligned.
      if (BaseAlignment.getQuantity() >= Alignment &&
          PtrAlign.getQuantity() < Alignment)
        return Success(0, E);
      // Otherwise we can't infer whether the value is sufficiently aligned.
      // TODO: __builtin_is_aligned(__builtin_align_{down,up{(expr, N), N)
      //  in cases where we can't fully evaluate the pointer.
      Info.FFDiag(E->getArg(0), diag::note_constexpr_alignment_compute)
          << Alignment;
      return false;
    }
    assert(Src.isInt());
    return Success((Src.getInt() & (Alignment - 1)) == 0 ? 1 : 0, E);
  }
  case Builtin::BI__builtin_align_up: {
    APValue Src;
    APSInt Alignment;
    if (!getBuiltinAlignArguments(E, Info, Src, Alignment))
      return false;
    if (!Src.isInt())
      return Error(E);
    APSInt AlignedVal =
        APSInt((Src.getInt() + (Alignment - 1)) & ~(Alignment - 1),
               Src.getInt().isUnsigned());
    assert(AlignedVal.getBitWidth() == Src.getInt().getBitWidth());
    return Success(AlignedVal, E);
  }
  case Builtin::BI__builtin_align_down: {
    APValue Src;
    APSInt Alignment;
    if (!getBuiltinAlignArguments(E, Info, Src, Alignment))
      return false;
    if (!Src.isInt())
      return Error(E);
    APSInt AlignedVal =
        APSInt(Src.getInt() & ~(Alignment - 1), Src.getInt().isUnsigned());
    assert(AlignedVal.getBitWidth() == Src.getInt().getBitWidth());
    return Success(AlignedVal, E);
  }

  case Builtin::BI__builtin_bswap16:
  case Builtin::BI__builtin_bswap32:
  case Builtin::BI__builtin_bswap64: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;

    return Success(Val.byteSwap(), E);
  }

  case Builtin::BI__builtin_classify_type:
    return Success((int)EvaluateBuiltinClassifyType(E, Info.getLangOpts()), E);

  case Builtin::BI__builtin_clrsb:
  case Builtin::BI__builtin_clrsbl:
  case Builtin::BI__builtin_clrsbll: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;

    return Success(Val.getBitWidth() - Val.getMinSignedBits(), E);
  }

  case Builtin::BI__builtin_clz:
  case Builtin::BI__builtin_clzl:
  case Builtin::BI__builtin_clzll:
  case Builtin::BI__builtin_clzs: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;
    if (!Val)
      return Error(E);

    return Success(Val.countLeadingZeros(), E);
  }

  case Builtin::BI__builtin_constant_p: {
    const Expr *Arg = E->getArg(0);
    if (EvaluateBuiltinConstantP(Info, Arg))
      return Success(true, E);
    if (Info.InConstantContext || Arg->HasSideEffects(Info.Ctx)) {
      // Outside a constant context, eagerly evaluate to false in the presence
      // of side-effects in order to avoid -Wunsequenced false-positives in
      // a branch on __builtin_constant_p(expr).
      return Success(false, E);
    }
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  case Builtin::BI__builtin_is_constant_evaluated: {
    const auto *Callee = Info.CurrentCall->getCallee();
    if (Info.InConstantContext && !Info.CheckingPotentialConstantExpression &&
        (Info.CallStackDepth == 1 ||
         (Info.CallStackDepth == 2 && Callee->isInStdNamespace() &&
          Callee->getIdentifier() &&
          Callee->getIdentifier()->isStr("is_constant_evaluated")))) {
      // FIXME: Find a better way to avoid duplicated diagnostics.
      if (Info.EvalStatus.Diag)
        Info.report((Info.CallStackDepth == 1) ? E->getExprLoc()
                                               : Info.CurrentCall->CallLoc,
                    diag::warn_is_constant_evaluated_always_true_constexpr)
            << (Info.CallStackDepth == 1 ? "__builtin_is_constant_evaluated"
                                         : "std::is_constant_evaluated");
    }

    return Success(Info.InConstantContext, E);
  }

  case Builtin::BI__builtin_ctz:
  case Builtin::BI__builtin_ctzl:
  case Builtin::BI__builtin_ctzll:
  case Builtin::BI__builtin_ctzs: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;
    if (!Val)
      return Error(E);

    return Success(Val.countTrailingZeros(), E);
  }

  case Builtin::BI__builtin_eh_return_data_regno: {
    int Operand = E->getArg(0)->EvaluateKnownConstInt(Info.Ctx).getZExtValue();
    Operand = Info.Ctx.getTargetInfo().getEHDataRegisterNumber(Operand);
    return Success(Operand, E);
  }

  case Builtin::BI__builtin_expect:
    return Visit(E->getArg(0));

  case Builtin::BI__builtin_ffs:
  case Builtin::BI__builtin_ffsl:
  case Builtin::BI__builtin_ffsll: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;

    unsigned N = Val.countTrailingZeros();
    return Success(N == Val.getBitWidth() ? 0 : N + 1, E);
  }

  case Builtin::BI__builtin_fpclassify: {
    APFloat Val(0.0);
    if (!EvaluateFloat(E->getArg(5), Val, Info))
      return false;
    unsigned Arg;
    switch (Val.getCategory()) {
    case APFloat::fcNaN: Arg = 0; break;
    case APFloat::fcInfinity: Arg = 1; break;
    case APFloat::fcNormal: Arg = Val.isDenormal() ? 3 : 2; break;
    case APFloat::fcZero: Arg = 4; break;
    }
    return Visit(E->getArg(Arg));
  }

  case Builtin::BI__builtin_isinf_sign: {
    APFloat Val(0.0);
    return EvaluateFloat(E->getArg(0), Val, Info) &&
           Success(Val.isInfinity() ? (Val.isNegative() ? -1 : 1) : 0, E);
  }

  case Builtin::BI__builtin_isinf: {
    APFloat Val(0.0);
    return EvaluateFloat(E->getArg(0), Val, Info) &&
           Success(Val.isInfinity() ? 1 : 0, E);
  }

  case Builtin::BI__builtin_isfinite: {
    APFloat Val(0.0);
    return EvaluateFloat(E->getArg(0), Val, Info) &&
           Success(Val.isFinite() ? 1 : 0, E);
  }

  case Builtin::BI__builtin_isnan: {
    APFloat Val(0.0);
    return EvaluateFloat(E->getArg(0), Val, Info) &&
           Success(Val.isNaN() ? 1 : 0, E);
  }

  case Builtin::BI__builtin_isnormal: {
    APFloat Val(0.0);
    return EvaluateFloat(E->getArg(0), Val, Info) &&
           Success(Val.isNormal() ? 1 : 0, E);
  }

  case Builtin::BI__builtin_parity:
  case Builtin::BI__builtin_parityl:
  case Builtin::BI__builtin_parityll: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;

    return Success(Val.countPopulation() % 2, E);
  }

  case Builtin::BI__builtin_popcount:
  case Builtin::BI__builtin_popcountl:
  case Builtin::BI__builtin_popcountll: {
    APSInt Val;
    if (!EvaluateInteger(E->getArg(0), Val, Info))
      return false;

    return Success(Val.countPopulation(), E);
  }

  case Builtin::BIstrlen:
  case Builtin::BIwcslen:
    // A call to strlen is not a constant expression.
    if (Info.getLangOpts().CPlusPlus11)
      Info.CCEDiag(E, diag::note_constexpr_invalid_function)
        << /*isConstexpr*/0 << /*isConstructor*/0
        << (std::string("'") + Info.Ctx.BuiltinInfo.getName(BuiltinOp) + "'");
    else
      Info.CCEDiag(E, diag::note_invalid_subexpr_in_const_expr);
    LLVM_FALLTHROUGH;
  case Builtin::BI__builtin_strlen:
  case Builtin::BI__builtin_wcslen: {
    // As an extension, we support __builtin_strlen() as a constant expression,
    // and support folding strlen() to a constant.
    LValue String;
    if (!EvaluatePointer(E->getArg(0), String, Info))
      return false;

    QualType CharTy = E->getArg(0)->getType()->getPointeeType();

    // Fast path: if it's a string literal, search the string value.
    if (const StringLiteral *S = dyn_cast_or_null<StringLiteral>(
            String.getLValueBase().dyn_cast<const Expr *>())) {
      // The string literal may have embedded null characters. Find the first
      // one and truncate there.
      StringRef Str = S->getBytes();
      int64_t Off = String.Offset.getQuantity();
      if (Off >= 0 && (uint64_t)Off <= (uint64_t)Str.size() &&
          S->getCharByteWidth() == 1 &&
          // FIXME: Add fast-path for wchar_t too.
          Info.Ctx.hasSameUnqualifiedType(CharTy, Info.Ctx.CharTy)) {
        Str = Str.substr(Off);

        StringRef::size_type Pos = Str.find(0);
        if (Pos != StringRef::npos)
          Str = Str.substr(0, Pos);

        return Success(Str.size(), E);
      }

      // Fall through to slow path to issue appropriate diagnostic.
    }

    // Slow path: scan the bytes of the string looking for the terminating 0.
    for (uint64_t Strlen = 0; /**/; ++Strlen) {
      APValue Char;
      if (!handleLValueToRValueConversion(Info, E, CharTy, String, Char) ||
          !Char.isInt())
        return false;
      if (!Char.getInt())
        return Success(Strlen, E);
      if (!HandleLValueArrayAdjustment(Info, E, String, CharTy, 1))
        return false;
    }
  }

  case Builtin::BIstrcmp:
  case Builtin::BIwcscmp:
  case Builtin::BIstrncmp:
  case Builtin::BIwcsncmp:
  case Builtin::BImemcmp:
  case Builtin::BIbcmp:
  case Builtin::BIwmemcmp:
    // A call to strlen is not a constant expression.
    if (Info.getLangOpts().CPlusPlus11)
      Info.CCEDiag(E, diag::note_constexpr_invalid_function)
        << /*isConstexpr*/0 << /*isConstructor*/0
        << (std::string("'") + Info.Ctx.BuiltinInfo.getName(BuiltinOp) + "'");
    else
      Info.CCEDiag(E, diag::note_invalid_subexpr_in_const_expr);
    LLVM_FALLTHROUGH;
  case Builtin::BI__builtin_strcmp:
  case Builtin::BI__builtin_wcscmp:
  case Builtin::BI__builtin_strncmp:
  case Builtin::BI__builtin_wcsncmp:
  case Builtin::BI__builtin_memcmp:
  case Builtin::BI__builtin_bcmp:
  case Builtin::BI__builtin_wmemcmp: {
    LValue String1, String2;
    if (!EvaluatePointer(E->getArg(0), String1, Info) ||
        !EvaluatePointer(E->getArg(1), String2, Info))
      return false;

    uint64_t MaxLength = uint64_t(-1);
    if (BuiltinOp != Builtin::BIstrcmp &&
        BuiltinOp != Builtin::BIwcscmp &&
        BuiltinOp != Builtin::BI__builtin_strcmp &&
        BuiltinOp != Builtin::BI__builtin_wcscmp) {
      APSInt N;
      if (!EvaluateInteger(E->getArg(2), N, Info))
        return false;
      MaxLength = N.getExtValue();
    }

    // Empty substrings compare equal by definition.
    if (MaxLength == 0u)
      return Success(0, E);

    if (!String1.checkNullPointerForFoldAccess(Info, E, AK_Read) ||
        !String2.checkNullPointerForFoldAccess(Info, E, AK_Read) ||
        String1.Designator.Invalid || String2.Designator.Invalid)
      return false;

    QualType CharTy1 = String1.Designator.getType(Info.Ctx);
    QualType CharTy2 = String2.Designator.getType(Info.Ctx);

    bool IsRawByte = BuiltinOp == Builtin::BImemcmp ||
                     BuiltinOp == Builtin::BIbcmp ||
                     BuiltinOp == Builtin::BI__builtin_memcmp ||
                     BuiltinOp == Builtin::BI__builtin_bcmp;

    assert(IsRawByte ||
           (Info.Ctx.hasSameUnqualifiedType(
                CharTy1, E->getArg(0)->getType()->getPointeeType()) &&
            Info.Ctx.hasSameUnqualifiedType(CharTy1, CharTy2)));

    const auto &ReadCurElems = [&](APValue &Char1, APValue &Char2) {
      return handleLValueToRValueConversion(Info, E, CharTy1, String1, Char1) &&
             handleLValueToRValueConversion(Info, E, CharTy2, String2, Char2) &&
             Char1.isInt() && Char2.isInt();
    };
    const auto &AdvanceElems = [&] {
      return HandleLValueArrayAdjustment(Info, E, String1, CharTy1, 1) &&
             HandleLValueArrayAdjustment(Info, E, String2, CharTy2, 1);
    };

    if (IsRawByte) {
      uint64_t BytesRemaining = MaxLength;
      // Pointers to const void may point to objects of incomplete type.
      if (CharTy1->isIncompleteType()) {
        Info.FFDiag(E, diag::note_constexpr_ltor_incomplete_type) << CharTy1;
        return false;
      }
      if (CharTy2->isIncompleteType()) {
        Info.FFDiag(E, diag::note_constexpr_ltor_incomplete_type) << CharTy2;
        return false;
      }
      uint64_t CharTy1Width{Info.Ctx.getTypeSize(CharTy1)};
      CharUnits CharTy1Size = Info.Ctx.toCharUnitsFromBits(CharTy1Width);
      // Give up on comparing between elements with disparate widths.
      if (CharTy1Size != Info.Ctx.getTypeSizeInChars(CharTy2))
        return false;
      uint64_t BytesPerElement = CharTy1Size.getQuantity();
      assert(BytesRemaining && "BytesRemaining should not be zero: the "
                               "following loop considers at least one element");
      while (true) {
        APValue Char1, Char2;
        if (!ReadCurElems(Char1, Char2))
          return false;
        // We have compatible in-memory widths, but a possible type and
        // (for `bool`) internal representation mismatch.
        // Assuming two's complement representation, including 0 for `false` and
        // 1 for `true`, we can check an appropriate number of elements for
        // equality even if they are not byte-sized.
        APSInt Char1InMem = Char1.getInt().extOrTrunc(CharTy1Width);
        APSInt Char2InMem = Char2.getInt().extOrTrunc(CharTy1Width);
        if (Char1InMem.ne(Char2InMem)) {
          // If the elements are byte-sized, then we can produce a three-way
          // comparison result in a straightforward manner.
          if (BytesPerElement == 1u) {
            // memcmp always compares unsigned chars.
            return Success(Char1InMem.ult(Char2InMem) ? -1 : 1, E);
          }
          // The result is byte-order sensitive, and we have multibyte elements.
          // FIXME: We can compare the remaining bytes in the correct order.
          return false;
        }
        if (!AdvanceElems())
          return false;
        if (BytesRemaining <= BytesPerElement)
          break;
        BytesRemaining -= BytesPerElement;
      }
      // Enough elements are equal to account for the memcmp limit.
      return Success(0, E);
    }

    bool StopAtNull =
        (BuiltinOp != Builtin::BImemcmp && BuiltinOp != Builtin::BIbcmp &&
         BuiltinOp != Builtin::BIwmemcmp &&
         BuiltinOp != Builtin::BI__builtin_memcmp &&
         BuiltinOp != Builtin::BI__builtin_bcmp &&
         BuiltinOp != Builtin::BI__builtin_wmemcmp);
    bool IsWide = BuiltinOp == Builtin::BIwcscmp ||
                  BuiltinOp == Builtin::BIwcsncmp ||
                  BuiltinOp == Builtin::BIwmemcmp ||
                  BuiltinOp == Builtin::BI__builtin_wcscmp ||
                  BuiltinOp == Builtin::BI__builtin_wcsncmp ||
                  BuiltinOp == Builtin::BI__builtin_wmemcmp;

    for (; MaxLength; --MaxLength) {
      APValue Char1, Char2;
      if (!ReadCurElems(Char1, Char2))
        return false;
      if (Char1.getInt() != Char2.getInt()) {
        if (IsWide) // wmemcmp compares with wchar_t signedness.
          return Success(Char1.getInt() < Char2.getInt() ? -1 : 1, E);
        // memcmp always compares unsigned chars.
        return Success(Char1.getInt().ult(Char2.getInt()) ? -1 : 1, E);
      }
      if (StopAtNull && !Char1.getInt())
        return Success(0, E);
      assert(!(StopAtNull && !Char2.getInt()));
      if (!AdvanceElems())
        return false;
    }
    // We hit the strncmp / memcmp limit.
    return Success(0, E);
  }

  case Builtin::BI__atomic_always_lock_free:
  case Builtin::BI__atomic_is_lock_free:
  case Builtin::BI__c11_atomic_is_lock_free: {
    APSInt SizeVal;
    if (!EvaluateInteger(E->getArg(0), SizeVal, Info))
      return false;

    // For __atomic_is_lock_free(sizeof(_Atomic(T))), if the size is a power
    // of two less than the maximum inline atomic width, we know it is
    // lock-free.  If the size isn't a power of two, or greater than the
    // maximum alignment where we promote atomics, we know it is not lock-free
    // (at least not in the sense of atomic_is_lock_free).  Otherwise,
    // the answer can only be determined at runtime; for example, 16-byte
    // atomics have lock-free implementations on some, but not all,
    // x86-64 processors.

    // Check power-of-two.
    CharUnits Size = CharUnits::fromQuantity(SizeVal.getZExtValue());
    if (Size.isPowerOfTwo()) {
      // Check against inlining width.
      unsigned InlineWidthBits =
          Info.Ctx.getTargetInfo().getMaxAtomicInlineWidth();
      if (Size <= Info.Ctx.toCharUnitsFromBits(InlineWidthBits)) {
        if (BuiltinOp == Builtin::BI__c11_atomic_is_lock_free ||
            Size == CharUnits::One() ||
            E->getArg(1)->isNullPointerConstant(Info.Ctx,
                                                Expr::NPC_NeverValueDependent))
          // OK, we will inline appropriately-aligned operations of this size,
          // and _Atomic(T) is appropriately-aligned.
          return Success(1, E);

        QualType PointeeType = E->getArg(1)->IgnoreImpCasts()->getType()->
          castAs<PointerType>()->getPointeeType();
        if (!PointeeType->isIncompleteType() &&
            Info.Ctx.getTypeAlignInChars(PointeeType) >= Size) {
          // OK, we will inline operations on this object.
          return Success(1, E);
        }
      }
    }

    // Avoid emiting call for runtime decision on PowerPC 32-bit
    // The lock free possibilities on this platform are covered by the lines 
    // above and we know in advance other cases require lock
    if (Info.Ctx.getTargetInfo().getTriple().getArch() == llvm::Triple::ppc) {
        return Success(0, E);
    }

    return BuiltinOp == Builtin::BI__atomic_always_lock_free ?
        Success(0, E) : Error(E);
  }
  case Builtin::BIomp_is_initial_device:
    // We can decide statically which value the runtime would return if called.
    return Success(Info.getLangOpts().OpenMPIsDevice ? 0 : 1, E);
  case Builtin::BI__builtin_add_overflow:
  case Builtin::BI__builtin_sub_overflow:
  case Builtin::BI__builtin_mul_overflow:
  case Builtin::BI__builtin_sadd_overflow:
  case Builtin::BI__builtin_uadd_overflow:
  case Builtin::BI__builtin_uaddl_overflow:
  case Builtin::BI__builtin_uaddll_overflow:
  case Builtin::BI__builtin_usub_overflow:
  case Builtin::BI__builtin_usubl_overflow:
  case Builtin::BI__builtin_usubll_overflow:
  case Builtin::BI__builtin_umul_overflow:
  case Builtin::BI__builtin_umull_overflow:
  case Builtin::BI__builtin_umulll_overflow:
  case Builtin::BI__builtin_saddl_overflow:
  case Builtin::BI__builtin_saddll_overflow:
  case Builtin::BI__builtin_ssub_overflow:
  case Builtin::BI__builtin_ssubl_overflow:
  case Builtin::BI__builtin_ssubll_overflow:
  case Builtin::BI__builtin_smul_overflow:
  case Builtin::BI__builtin_smull_overflow:
  case Builtin::BI__builtin_smulll_overflow: {
    LValue ResultLValue;
    APSInt LHS, RHS;

    QualType ResultType = E->getArg(2)->getType()->getPointeeType();
    if (!EvaluateInteger(E->getArg(0), LHS, Info) ||
        !EvaluateInteger(E->getArg(1), RHS, Info) ||
        !EvaluatePointer(E->getArg(2), ResultLValue, Info))
      return false;

    APSInt Result;
    bool DidOverflow = false;

    // If the types don't have to match, enlarge all 3 to the largest of them.
    if (BuiltinOp == Builtin::BI__builtin_add_overflow ||
        BuiltinOp == Builtin::BI__builtin_sub_overflow ||
        BuiltinOp == Builtin::BI__builtin_mul_overflow) {
      bool IsSigned = LHS.isSigned() || RHS.isSigned() ||
                      ResultType->isSignedIntegerOrEnumerationType();
      bool AllSigned = LHS.isSigned() && RHS.isSigned() &&
                      ResultType->isSignedIntegerOrEnumerationType();
      uint64_t LHSSize = LHS.getBitWidth();
      uint64_t RHSSize = RHS.getBitWidth();
      uint64_t ResultSize = Info.Ctx.getTypeSize(ResultType);
      uint64_t MaxBits = std::max(std::max(LHSSize, RHSSize), ResultSize);

      // Add an additional bit if the signedness isn't uniformly agreed to. We
      // could do this ONLY if there is a signed and an unsigned that both have
      // MaxBits, but the code to check that is pretty nasty.  The issue will be
      // caught in the shrink-to-result later anyway.
      if (IsSigned && !AllSigned)
        ++MaxBits;

      LHS = APSInt(LHS.extOrTrunc(MaxBits), !IsSigned);
      RHS = APSInt(RHS.extOrTrunc(MaxBits), !IsSigned);
      Result = APSInt(MaxBits, !IsSigned);
    }

    // Find largest int.
    switch (BuiltinOp) {
    default:
      llvm_unreachable("Invalid value for BuiltinOp");
    case Builtin::BI__builtin_add_overflow:
    case Builtin::BI__builtin_sadd_overflow:
    case Builtin::BI__builtin_saddl_overflow:
    case Builtin::BI__builtin_saddll_overflow:
    case Builtin::BI__builtin_uadd_overflow:
    case Builtin::BI__builtin_uaddl_overflow:
    case Builtin::BI__builtin_uaddll_overflow:
      Result = LHS.isSigned() ? LHS.sadd_ov(RHS, DidOverflow)
                              : LHS.uadd_ov(RHS, DidOverflow);
      break;
    case Builtin::BI__builtin_sub_overflow:
    case Builtin::BI__builtin_ssub_overflow:
    case Builtin::BI__builtin_ssubl_overflow:
    case Builtin::BI__builtin_ssubll_overflow:
    case Builtin::BI__builtin_usub_overflow:
    case Builtin::BI__builtin_usubl_overflow:
    case Builtin::BI__builtin_usubll_overflow:
      Result = LHS.isSigned() ? LHS.ssub_ov(RHS, DidOverflow)
                              : LHS.usub_ov(RHS, DidOverflow);
      break;
    case Builtin::BI__builtin_mul_overflow:
    case Builtin::BI__builtin_smul_overflow:
    case Builtin::BI__builtin_smull_overflow:
    case Builtin::BI__builtin_smulll_overflow:
    case Builtin::BI__builtin_umul_overflow:
    case Builtin::BI__builtin_umull_overflow:
    case Builtin::BI__builtin_umulll_overflow:
      Result = LHS.isSigned() ? LHS.smul_ov(RHS, DidOverflow)
                              : LHS.umul_ov(RHS, DidOverflow);
      break;
    }

    // In the case where multiple sizes are allowed, truncate and see if
    // the values are the same.
    if (BuiltinOp == Builtin::BI__builtin_add_overflow ||
        BuiltinOp == Builtin::BI__builtin_sub_overflow ||
        BuiltinOp == Builtin::BI__builtin_mul_overflow) {
      // APSInt doesn't have a TruncOrSelf, so we use extOrTrunc instead,
      // since it will give us the behavior of a TruncOrSelf in the case where
      // its parameter <= its size.  We previously set Result to be at least the
      // type-size of the result, so getTypeSize(ResultType) <= Result.BitWidth
      // will work exactly like TruncOrSelf.
      APSInt Temp = Result.extOrTrunc(Info.Ctx.getTypeSize(ResultType));
      Temp.setIsSigned(ResultType->isSignedIntegerOrEnumerationType());

      if (!APSInt::isSameValue(Temp, Result))
        DidOverflow = true;
      Result = Temp;
    }

    APValue APV{Result};
    if (!handleAssignment(Info, E, ResultLValue, ResultType, APV))
      return false;
    return Success(DidOverflow, E);
  }
  }
}

/// Determine whether this is a pointer past the end of the complete
/// object referred to by the lvalue.
static bool isOnePastTheEndOfCompleteObject(const ASTContext &Ctx,
                                            const LValue &LV) {
  // A null pointer can be viewed as being "past the end" but we don't
  // choose to look at it that way here.
  if (!LV.getLValueBase())
    return false;

  // If the designator is valid and refers to a subobject, we're not pointing
  // past the end.
  if (!LV.getLValueDesignator().Invalid &&
      !LV.getLValueDesignator().isOnePastTheEnd())
    return false;

  // A pointer to an incomplete type might be past-the-end if the type's size is
  // zero.  We cannot tell because the type is incomplete.
  QualType Ty = getType(LV.getLValueBase());
  if (Ty->isIncompleteType())
    return true;

  // We're a past-the-end pointer if we point to the byte after the object,
  // no matter what our type or path is.
  auto Size = Ctx.getTypeSizeInChars(Ty);
  return LV.getLValueOffset() == Size;
}

namespace {

/// Data recursive integer evaluator of certain binary operators.
///
/// We use a data recursive algorithm for binary operators so that we are able
/// to handle extreme cases of chained binary operators without causing stack
/// overflow.
class DataRecursiveIntBinOpEvaluator {
  struct EvalResult {
    APValue Val;
    bool Failed;

    EvalResult() : Failed(false) { }

    void swap(EvalResult &RHS) {
      Val.swap(RHS.Val);
      Failed = RHS.Failed;
      RHS.Failed = false;
    }
  };

  struct Job {
    const Expr *E;
    EvalResult LHSResult; // meaningful only for binary operator expression.
    enum { AnyExprKind, BinOpKind, BinOpVisitedLHSKind } Kind;

    Job() = default;
    Job(Job &&) = default;

    void startSpeculativeEval(EvalInfo &Info) {
      SpecEvalRAII = SpeculativeEvaluationRAII(Info);
    }

  private:
    SpeculativeEvaluationRAII SpecEvalRAII;
  };

  SmallVector<Job, 16> Queue;

  IntExprEvaluator &IntEval;
  EvalInfo &Info;
  APValue &FinalResult;

public:
  DataRecursiveIntBinOpEvaluator(IntExprEvaluator &IntEval, APValue &Result)
    : IntEval(IntEval), Info(IntEval.getEvalInfo()), FinalResult(Result) { }

  /// True if \param E is a binary operator that we are going to handle
  /// data recursively.
  /// We handle binary operators that are comma, logical, or that have operands
  /// with integral or enumeration type.
  static bool shouldEnqueue(const BinaryOperator *E) {
    return E->getOpcode() == BO_Comma || E->isLogicalOp() ||
           (E->isRValue() && E->getType()->isIntegralOrEnumerationType() &&
            E->getLHS()->getType()->isIntegralOrEnumerationType() &&
            E->getRHS()->getType()->isIntegralOrEnumerationType());
  }

  bool Traverse(const BinaryOperator *E) {
    enqueue(E);
    EvalResult PrevResult;
    while (!Queue.empty())
      process(PrevResult);

    if (PrevResult.Failed) return false;

    FinalResult.swap(PrevResult.Val);
    return true;
  }

private:
  bool Success(uint64_t Value, const Expr *E, APValue &Result) {
    return IntEval.Success(Value, E, Result);
  }
  bool Success(const APSInt &Value, const Expr *E, APValue &Result) {
    return IntEval.Success(Value, E, Result);
  }
  bool Error(const Expr *E) {
    return IntEval.Error(E);
  }
  bool Error(const Expr *E, diag::kind D) {
    return IntEval.Error(E, D);
  }

  OptionalDiagnostic CCEDiag(const Expr *E, diag::kind D) {
    return Info.CCEDiag(E, D);
  }

  // Returns true if visiting the RHS is necessary, false otherwise.
  bool VisitBinOpLHSOnly(EvalResult &LHSResult, const BinaryOperator *E,
                         bool &SuppressRHSDiags);

  bool VisitBinOp(const EvalResult &LHSResult, const EvalResult &RHSResult,
                  const BinaryOperator *E, APValue &Result);

  void EvaluateExpr(const Expr *E, EvalResult &Result) {
    Result.Failed = !Evaluate(Result.Val, Info, E);
    if (Result.Failed)
      Result.Val = APValue();
  }

  void process(EvalResult &Result);

  void enqueue(const Expr *E) {
    E = E->IgnoreParens();
    Queue.resize(Queue.size()+1);
    Queue.back().E = E;
    Queue.back().Kind = Job::AnyExprKind;
  }
};

}

bool DataRecursiveIntBinOpEvaluator::
       VisitBinOpLHSOnly(EvalResult &LHSResult, const BinaryOperator *E,
                         bool &SuppressRHSDiags) {
  if (E->getOpcode() == BO_Comma) {
    // Ignore LHS but note if we could not evaluate it.
    if (LHSResult.Failed)
      return Info.noteSideEffect();
    return true;
  }

  if (E->isLogicalOp()) {
    bool LHSAsBool;
    if (!LHSResult.Failed && HandleConversionToBool(LHSResult.Val, LHSAsBool)) {
      // We were able to evaluate the LHS, see if we can get away with not
      // evaluating the RHS: 0 && X -> 0, 1 || X -> 1
      if (LHSAsBool == (E->getOpcode() == BO_LOr)) {
        Success(LHSAsBool, E, LHSResult.Val);
        return false; // Ignore RHS
      }
    } else {
      LHSResult.Failed = true;

      // Since we weren't able to evaluate the left hand side, it
      // might have had side effects.
      if (!Info.noteSideEffect())
        return false;

      // We can't evaluate the LHS; however, sometimes the result
      // is determined by the RHS: X && 0 -> 0, X || 1 -> 1.
      // Don't ignore RHS and suppress diagnostics from this arm.
      SuppressRHSDiags = true;
    }

    return true;
  }

  assert(E->getLHS()->getType()->isIntegralOrEnumerationType() &&
         E->getRHS()->getType()->isIntegralOrEnumerationType());

  if (LHSResult.Failed && !Info.noteFailure())
    return false; // Ignore RHS;

  return true;
}

static void addOrSubLValueAsInteger(APValue &LVal, const APSInt &Index,
                                    bool IsSub) {
  // Compute the new offset in the appropriate width, wrapping at 64 bits.
  // FIXME: When compiling for a 32-bit target, we should use 32-bit
  // offsets.
  assert(!LVal.hasLValuePath() && "have designator for integer lvalue");
  CharUnits &Offset = LVal.getLValueOffset();
  uint64_t Offset64 = Offset.getQuantity();
  uint64_t Index64 = Index.extOrTrunc(64).getZExtValue();
  Offset = CharUnits::fromQuantity(IsSub ? Offset64 - Index64
                                         : Offset64 + Index64);
}

bool DataRecursiveIntBinOpEvaluator::
       VisitBinOp(const EvalResult &LHSResult, const EvalResult &RHSResult,
                  const BinaryOperator *E, APValue &Result) {
  if (E->getOpcode() == BO_Comma) {
    if (RHSResult.Failed)
      return false;
    Result = RHSResult.Val;
    return true;
  }

  if (E->isLogicalOp()) {
    bool lhsResult, rhsResult;
    bool LHSIsOK = HandleConversionToBool(LHSResult.Val, lhsResult);
    bool RHSIsOK = HandleConversionToBool(RHSResult.Val, rhsResult);

    if (LHSIsOK) {
      if (RHSIsOK) {
        if (E->getOpcode() == BO_LOr)
          return Success(lhsResult || rhsResult, E, Result);
        else
          return Success(lhsResult && rhsResult, E, Result);
      }
    } else {
      if (RHSIsOK) {
        // We can't evaluate the LHS; however, sometimes the result
        // is determined by the RHS: X && 0 -> 0, X || 1 -> 1.
        if (rhsResult == (E->getOpcode() == BO_LOr))
          return Success(rhsResult, E, Result);
      }
    }

    return false;
  }

  assert(E->getLHS()->getType()->isIntegralOrEnumerationType() &&
         E->getRHS()->getType()->isIntegralOrEnumerationType());

  if (LHSResult.Failed || RHSResult.Failed)
    return false;

  const APValue &LHSVal = LHSResult.Val;
  const APValue &RHSVal = RHSResult.Val;

  // Handle cases like (unsigned long)&a + 4.
  if (E->isAdditiveOp() && LHSVal.isLValue() && RHSVal.isInt()) {
    Result = LHSVal;
    addOrSubLValueAsInteger(Result, RHSVal.getInt(), E->getOpcode() == BO_Sub);
    return true;
  }

  // Handle cases like 4 + (unsigned long)&a
  if (E->getOpcode() == BO_Add &&
      RHSVal.isLValue() && LHSVal.isInt()) {
    Result = RHSVal;
    addOrSubLValueAsInteger(Result, LHSVal.getInt(), /*IsSub*/false);
    return true;
  }

  if (E->getOpcode() == BO_Sub && LHSVal.isLValue() && RHSVal.isLValue()) {
    // Handle (intptr_t)&&A - (intptr_t)&&B.
    if (!LHSVal.getLValueOffset().isZero() ||
        !RHSVal.getLValueOffset().isZero())
      return false;
    const Expr *LHSExpr = LHSVal.getLValueBase().dyn_cast<const Expr*>();
    const Expr *RHSExpr = RHSVal.getLValueBase().dyn_cast<const Expr*>();
    if (!LHSExpr || !RHSExpr)
      return false;
    const AddrLabelExpr *LHSAddrExpr = dyn_cast<AddrLabelExpr>(LHSExpr);
    const AddrLabelExpr *RHSAddrExpr = dyn_cast<AddrLabelExpr>(RHSExpr);
    if (!LHSAddrExpr || !RHSAddrExpr)
      return false;
    // Make sure both labels come from the same function.
    if (LHSAddrExpr->getLabel()->getDeclContext() !=
        RHSAddrExpr->getLabel()->getDeclContext())
      return false;
    Result = APValue(LHSAddrExpr, RHSAddrExpr);
    return true;
  }

  // All the remaining cases expect both operands to be an integer
  if (!LHSVal.isInt() || !RHSVal.isInt())
    return Error(E);

  // Set up the width and signedness manually, in case it can't be deduced
  // from the operation we're performing.
  // FIXME: Don't do this in the cases where we can deduce it.
  APSInt Value(Info.Ctx.getIntWidth(E->getType()),
               E->getType()->isUnsignedIntegerOrEnumerationType());
  if (!handleIntIntBinOp(Info, E, LHSVal.getInt(), E->getOpcode(),
                         RHSVal.getInt(), Value))
    return false;
  return Success(Value, E, Result);
}

void DataRecursiveIntBinOpEvaluator::process(EvalResult &Result) {
  Job &job = Queue.back();

  switch (job.Kind) {
    case Job::AnyExprKind: {
      if (const BinaryOperator *Bop = dyn_cast<BinaryOperator>(job.E)) {
        if (shouldEnqueue(Bop)) {
          job.Kind = Job::BinOpKind;
          enqueue(Bop->getLHS());
          return;
        }
      }

      EvaluateExpr(job.E, Result);
      Queue.pop_back();
      return;
    }

    case Job::BinOpKind: {
      const BinaryOperator *Bop = cast<BinaryOperator>(job.E);
      bool SuppressRHSDiags = false;
      if (!VisitBinOpLHSOnly(Result, Bop, SuppressRHSDiags)) {
        Queue.pop_back();
        return;
      }
      if (SuppressRHSDiags)
        job.startSpeculativeEval(Info);
      job.LHSResult.swap(Result);
      job.Kind = Job::BinOpVisitedLHSKind;
      enqueue(Bop->getRHS());
      return;
    }

    case Job::BinOpVisitedLHSKind: {
      const BinaryOperator *Bop = cast<BinaryOperator>(job.E);
      EvalResult RHS;
      RHS.swap(Result);
      Result.Failed = !VisitBinOp(job.LHSResult, RHS, Bop, Result.Val);
      Queue.pop_back();
      return;
    }
  }

  llvm_unreachable("Invalid Job::Kind!");
}

namespace {
/// Used when we determine that we should fail, but can keep evaluating prior to
/// noting that we had a failure.
class DelayedNoteFailureRAII {
  EvalInfo &Info;
  bool NoteFailure;

public:
  DelayedNoteFailureRAII(EvalInfo &Info, bool NoteFailure = true)
      : Info(Info), NoteFailure(NoteFailure) {}
  ~DelayedNoteFailureRAII() {
    if (NoteFailure) {
      bool ContinueAfterFailure = Info.noteFailure();
      (void)ContinueAfterFailure;
      assert(ContinueAfterFailure &&
             "Shouldn't have kept evaluating on failure.");
    }
  }
};

enum class CmpResult {
  Unequal,
  Less,
  Equal,
  Greater,
  Unordered,
};
}

template <class SuccessCB, class AfterCB>
static bool
EvaluateComparisonBinaryOperator(EvalInfo &Info, const BinaryOperator *E,
                                 SuccessCB &&Success, AfterCB &&DoAfter) {
  assert(E->isComparisonOp() && "expected comparison operator");
  assert((E->getOpcode() == BO_Cmp ||
          E->getType()->isIntegralOrEnumerationType()) &&
         "unsupported binary expression evaluation");
  auto Error = [&](const Expr *E) {
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  };

  bool IsRelational = E->isRelationalOp() || E->getOpcode() == BO_Cmp;
  bool IsEquality = E->isEqualityOp();

  QualType LHSTy = E->getLHS()->getType();
  QualType RHSTy = E->getRHS()->getType();

  if (LHSTy->isIntegralOrEnumerationType() &&
      RHSTy->isIntegralOrEnumerationType()) {
    APSInt LHS, RHS;
    bool LHSOK = EvaluateInteger(E->getLHS(), LHS, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;
    if (!EvaluateInteger(E->getRHS(), RHS, Info) || !LHSOK)
      return false;
    if (LHS < RHS)
      return Success(CmpResult::Less, E);
    if (LHS > RHS)
      return Success(CmpResult::Greater, E);
    return Success(CmpResult::Equal, E);
  }

  if (LHSTy->isFixedPointType() || RHSTy->isFixedPointType()) {
    APFixedPoint LHSFX(Info.Ctx.getFixedPointSemantics(LHSTy));
    APFixedPoint RHSFX(Info.Ctx.getFixedPointSemantics(RHSTy));

    bool LHSOK = EvaluateFixedPointOrInteger(E->getLHS(), LHSFX, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;
    if (!EvaluateFixedPointOrInteger(E->getRHS(), RHSFX, Info) || !LHSOK)
      return false;
    if (LHSFX < RHSFX)
      return Success(CmpResult::Less, E);
    if (LHSFX > RHSFX)
      return Success(CmpResult::Greater, E);
    return Success(CmpResult::Equal, E);
  }

  if (LHSTy->isAnyComplexType() || RHSTy->isAnyComplexType()) {
    ComplexValue LHS, RHS;
    bool LHSOK;
    if (E->isAssignmentOp()) {
      LValue LV;
      EvaluateLValue(E->getLHS(), LV, Info);
      LHSOK = false;
    } else if (LHSTy->isRealFloatingType()) {
      LHSOK = EvaluateFloat(E->getLHS(), LHS.FloatReal, Info);
      if (LHSOK) {
        LHS.makeComplexFloat();
        LHS.FloatImag = APFloat(LHS.FloatReal.getSemantics());
      }
    } else {
      LHSOK = EvaluateComplex(E->getLHS(), LHS, Info);
    }
    if (!LHSOK && !Info.noteFailure())
      return false;

    if (E->getRHS()->getType()->isRealFloatingType()) {
      if (!EvaluateFloat(E->getRHS(), RHS.FloatReal, Info) || !LHSOK)
        return false;
      RHS.makeComplexFloat();
      RHS.FloatImag = APFloat(RHS.FloatReal.getSemantics());
    } else if (!EvaluateComplex(E->getRHS(), RHS, Info) || !LHSOK)
      return false;

    if (LHS.isComplexFloat()) {
      APFloat::cmpResult CR_r =
        LHS.getComplexFloatReal().compare(RHS.getComplexFloatReal());
      APFloat::cmpResult CR_i =
        LHS.getComplexFloatImag().compare(RHS.getComplexFloatImag());
      bool IsEqual = CR_r == APFloat::cmpEqual && CR_i == APFloat::cmpEqual;
      return Success(IsEqual ? CmpResult::Equal : CmpResult::Unequal, E);
    } else {
      assert(IsEquality && "invalid complex comparison");
      bool IsEqual = LHS.getComplexIntReal() == RHS.getComplexIntReal() &&
                     LHS.getComplexIntImag() == RHS.getComplexIntImag();
      return Success(IsEqual ? CmpResult::Equal : CmpResult::Unequal, E);
    }
  }

  if (LHSTy->isRealFloatingType() &&
      RHSTy->isRealFloatingType()) {
    APFloat RHS(0.0), LHS(0.0);

    bool LHSOK = EvaluateFloat(E->getRHS(), RHS, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;

    if (!EvaluateFloat(E->getLHS(), LHS, Info) || !LHSOK)
      return false;

    assert(E->isComparisonOp() && "Invalid binary operator!");
    auto GetCmpRes = [&]() {
      switch (LHS.compare(RHS)) {
      case APFloat::cmpEqual:
        return CmpResult::Equal;
      case APFloat::cmpLessThan:
        return CmpResult::Less;
      case APFloat::cmpGreaterThan:
        return CmpResult::Greater;
      case APFloat::cmpUnordered:
        return CmpResult::Unordered;
      }
      llvm_unreachable("Unrecognised APFloat::cmpResult enum");
    };
    return Success(GetCmpRes(), E);
  }

  if (LHSTy->isPointerType() && RHSTy->isPointerType()) {
    LValue LHSValue, RHSValue;

    bool LHSOK = EvaluatePointer(E->getLHS(), LHSValue, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;

    if (!EvaluatePointer(E->getRHS(), RHSValue, Info) || !LHSOK)
      return false;

    // Reject differing bases from the normal codepath; we special-case
    // comparisons to null.
    if (!HasSameBase(LHSValue, RHSValue)) {
      // Inequalities and subtractions between unrelated pointers have
      // unspecified or undefined behavior.
      if (!IsEquality) {
        Info.FFDiag(E, diag::note_constexpr_pointer_comparison_unspecified);
        return false;
      }
      // A constant address may compare equal to the address of a symbol.
      // The one exception is that address of an object cannot compare equal
      // to a null pointer constant.
      if ((!LHSValue.Base && !LHSValue.Offset.isZero()) ||
          (!RHSValue.Base && !RHSValue.Offset.isZero()))
        return Error(E);
      // It's implementation-defined whether distinct literals will have
      // distinct addresses. In clang, the result of such a comparison is
      // unspecified, so it is not a constant expression. However, we do know
      // that the address of a literal will be non-null.
      if ((IsLiteralLValue(LHSValue) || IsLiteralLValue(RHSValue)) &&
          LHSValue.Base && RHSValue.Base)
        return Error(E);
      // We can't tell whether weak symbols will end up pointing to the same
      // object.
      if (IsWeakLValue(LHSValue) || IsWeakLValue(RHSValue))
        return Error(E);
      // We can't compare the address of the start of one object with the
      // past-the-end address of another object, per C++ DR1652.
      if ((LHSValue.Base && LHSValue.Offset.isZero() &&
           isOnePastTheEndOfCompleteObject(Info.Ctx, RHSValue)) ||
          (RHSValue.Base && RHSValue.Offset.isZero() &&
           isOnePastTheEndOfCompleteObject(Info.Ctx, LHSValue)))
        return Error(E);
      // We can't tell whether an object is at the same address as another
      // zero sized object.
      if ((RHSValue.Base && isZeroSized(LHSValue)) ||
          (LHSValue.Base && isZeroSized(RHSValue)))
        return Error(E);
      return Success(CmpResult::Unequal, E);
    }

    const CharUnits &LHSOffset = LHSValue.getLValueOffset();
    const CharUnits &RHSOffset = RHSValue.getLValueOffset();

    SubobjectDesignator &LHSDesignator = LHSValue.getLValueDesignator();
    SubobjectDesignator &RHSDesignator = RHSValue.getLValueDesignator();

    // C++11 [expr.rel]p3:
    //   Pointers to void (after pointer conversions) can be compared, with a
    //   result defined as follows: If both pointers represent the same
    //   address or are both the null pointer value, the result is true if the
    //   operator is <= or >= and false otherwise; otherwise the result is
    //   unspecified.
    // We interpret this as applying to pointers to *cv* void.
    if (LHSTy->isVoidPointerType() && LHSOffset != RHSOffset && IsRelational)
      Info.CCEDiag(E, diag::note_constexpr_void_comparison);

    // C++11 [expr.rel]p2:
    // - If two pointers point to non-static data members of the same object,
    //   or to subobjects or array elements fo such members, recursively, the
    //   pointer to the later declared member compares greater provided the
    //   two members have the same access control and provided their class is
    //   not a union.
    //   [...]
    // - Otherwise pointer comparisons are unspecified.
    if (!LHSDesignator.Invalid && !RHSDesignator.Invalid && IsRelational) {
      bool WasArrayIndex;
      unsigned Mismatch = FindDesignatorMismatch(
          getType(LHSValue.Base), LHSDesignator, RHSDesignator, WasArrayIndex);
      // At the point where the designators diverge, the comparison has a
      // specified value if:
      //  - we are comparing array indices
      //  - we are comparing fields of a union, or fields with the same access
      // Otherwise, the result is unspecified and thus the comparison is not a
      // constant expression.
      if (!WasArrayIndex && Mismatch < LHSDesignator.Entries.size() &&
          Mismatch < RHSDesignator.Entries.size()) {
        const FieldDecl *LF = getAsField(LHSDesignator.Entries[Mismatch]);
        const FieldDecl *RF = getAsField(RHSDesignator.Entries[Mismatch]);
        if (!LF && !RF)
          Info.CCEDiag(E, diag::note_constexpr_pointer_comparison_base_classes);
        else if (!LF)
          Info.CCEDiag(E, diag::note_constexpr_pointer_comparison_base_field)
              << getAsBaseClass(LHSDesignator.Entries[Mismatch])
              << RF->getParent() << RF;
        else if (!RF)
          Info.CCEDiag(E, diag::note_constexpr_pointer_comparison_base_field)
              << getAsBaseClass(RHSDesignator.Entries[Mismatch])
              << LF->getParent() << LF;
        else if (!LF->getParent()->isUnion() &&
                 LF->getAccess() != RF->getAccess())
          Info.CCEDiag(E,
                       diag::note_constexpr_pointer_comparison_differing_access)
              << LF << LF->getAccess() << RF << RF->getAccess()
              << LF->getParent();
      }
    }

    // The comparison here must be unsigned, and performed with the same
    // width as the pointer.
    unsigned PtrSize = Info.Ctx.getTypeSize(LHSTy);
    uint64_t CompareLHS = LHSOffset.getQuantity();
    uint64_t CompareRHS = RHSOffset.getQuantity();
    assert(PtrSize <= 64 && "Unexpected pointer width");
    uint64_t Mask = ~0ULL >> (64 - PtrSize);
    CompareLHS &= Mask;
    CompareRHS &= Mask;

    // If there is a base and this is a relational operator, we can only
    // compare pointers within the object in question; otherwise, the result
    // depends on where the object is located in memory.
    if (!LHSValue.Base.isNull() && IsRelational) {
      QualType BaseTy = getType(LHSValue.Base);
      if (BaseTy->isIncompleteType())
        return Error(E);
      CharUnits Size = Info.Ctx.getTypeSizeInChars(BaseTy);
      uint64_t OffsetLimit = Size.getQuantity();
      if (CompareLHS > OffsetLimit || CompareRHS > OffsetLimit)
        return Error(E);
    }

    if (CompareLHS < CompareRHS)
      return Success(CmpResult::Less, E);
    if (CompareLHS > CompareRHS)
      return Success(CmpResult::Greater, E);
    return Success(CmpResult::Equal, E);
  }

  if (LHSTy->isMemberPointerType()) {
    assert(IsEquality && "unexpected member pointer operation");
    assert(RHSTy->isMemberPointerType() && "invalid comparison");

    MemberPtr LHSValue, RHSValue;

    bool LHSOK = EvaluateMemberPointer(E->getLHS(), LHSValue, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;

    if (!EvaluateMemberPointer(E->getRHS(), RHSValue, Info) || !LHSOK)
      return false;

    // C++11 [expr.eq]p2:
    //   If both operands are null, they compare equal. Otherwise if only one is
    //   null, they compare unequal.
    if (!LHSValue.getDecl() || !RHSValue.getDecl()) {
      bool Equal = !LHSValue.getDecl() && !RHSValue.getDecl();
      return Success(Equal ? CmpResult::Equal : CmpResult::Unequal, E);
    }

    //   Otherwise if either is a pointer to a virtual member function, the
    //   result is unspecified.
    if (const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(LHSValue.getDecl()))
      if (MD->isVirtual())
        Info.CCEDiag(E, diag::note_constexpr_compare_virtual_mem_ptr) << MD;
    if (const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(RHSValue.getDecl()))
      if (MD->isVirtual())
        Info.CCEDiag(E, diag::note_constexpr_compare_virtual_mem_ptr) << MD;

    //   Otherwise they compare equal if and only if they would refer to the
    //   same member of the same most derived object or the same subobject if
    //   they were dereferenced with a hypothetical object of the associated
    //   class type.
    bool Equal = LHSValue == RHSValue;
    return Success(Equal ? CmpResult::Equal : CmpResult::Unequal, E);
  }

  if (LHSTy->isNullPtrType()) {
    assert(E->isComparisonOp() && "unexpected nullptr operation");
    assert(RHSTy->isNullPtrType() && "missing pointer conversion");
    // C++11 [expr.rel]p4, [expr.eq]p3: If two operands of type std::nullptr_t
    // are compared, the result is true of the operator is <=, >= or ==, and
    // false otherwise.
    return Success(CmpResult::Equal, E);
  }

  return DoAfter();
}

bool RecordExprEvaluator::VisitBinCmp(const BinaryOperator *E) {
  if (!CheckLiteralType(Info, E))
    return false;

  auto OnSuccess = [&](CmpResult CR, const BinaryOperator *E) {
    ComparisonCategoryResult CCR;
    switch (CR) {
    case CmpResult::Unequal:
      llvm_unreachable("should never produce Unequal for three-way comparison");
    case CmpResult::Less:
      CCR = ComparisonCategoryResult::Less;
      break;
    case CmpResult::Equal:
      CCR = ComparisonCategoryResult::Equal;
      break;
    case CmpResult::Greater:
      CCR = ComparisonCategoryResult::Greater;
      break;
    case CmpResult::Unordered:
      CCR = ComparisonCategoryResult::Unordered;
      break;
    }
    // Evaluation succeeded. Lookup the information for the comparison category
    // type and fetch the VarDecl for the result.
    const ComparisonCategoryInfo &CmpInfo =
        Info.Ctx.CompCategories.getInfoForType(E->getType());
    const VarDecl *VD = CmpInfo.getValueInfo(CmpInfo.makeWeakResult(CCR))->VD;
    // Check and evaluate the result as a constant expression.
    LValue LV;
    LV.set(VD);
    if (!handleLValueToRValueConversion(Info, E, E->getType(), LV, Result))
      return false;
    return CheckConstantExpression(Info, E->getExprLoc(), E->getType(), Result);
  };
  return EvaluateComparisonBinaryOperator(Info, E, OnSuccess, [&]() {
    return ExprEvaluatorBaseTy::VisitBinCmp(E);
  });
}

bool IntExprEvaluator::VisitBinaryOperator(const BinaryOperator *E) {
  // We don't call noteFailure immediately because the assignment happens after
  // we evaluate LHS and RHS.
  if (!Info.keepEvaluatingAfterFailure() && E->isAssignmentOp())
    return Error(E);

  DelayedNoteFailureRAII MaybeNoteFailureLater(Info, E->isAssignmentOp());
  if (DataRecursiveIntBinOpEvaluator::shouldEnqueue(E))
    return DataRecursiveIntBinOpEvaluator(*this, Result).Traverse(E);

  assert((!E->getLHS()->getType()->isIntegralOrEnumerationType() ||
          !E->getRHS()->getType()->isIntegralOrEnumerationType()) &&
         "DataRecursiveIntBinOpEvaluator should have handled integral types");

  if (E->isComparisonOp()) {
    // Evaluate builtin binary comparisons by evaluating them as three-way
    // comparisons and then translating the result.
    auto OnSuccess = [&](CmpResult CR, const BinaryOperator *E) {
      assert((CR != CmpResult::Unequal || E->isEqualityOp()) &&
             "should only produce Unequal for equality comparisons");
      bool IsEqual   = CR == CmpResult::Equal,
           IsLess    = CR == CmpResult::Less,
           IsGreater = CR == CmpResult::Greater;
      auto Op = E->getOpcode();
      switch (Op) {
      default:
        llvm_unreachable("unsupported binary operator");
      case BO_EQ:
      case BO_NE:
        return Success(IsEqual == (Op == BO_EQ), E);
      case BO_LT:
        return Success(IsLess, E);
      case BO_GT:
        return Success(IsGreater, E);
      case BO_LE:
        return Success(IsEqual || IsLess, E);
      case BO_GE:
        return Success(IsEqual || IsGreater, E);
      }
    };
    return EvaluateComparisonBinaryOperator(Info, E, OnSuccess, [&]() {
      return ExprEvaluatorBaseTy::VisitBinaryOperator(E);
    });
  }

  QualType LHSTy = E->getLHS()->getType();
  QualType RHSTy = E->getRHS()->getType();

  if (LHSTy->isPointerType() && RHSTy->isPointerType() &&
      E->getOpcode() == BO_Sub) {
    LValue LHSValue, RHSValue;

    bool LHSOK = EvaluatePointer(E->getLHS(), LHSValue, Info);
    if (!LHSOK && !Info.noteFailure())
      return false;

    if (!EvaluatePointer(E->getRHS(), RHSValue, Info) || !LHSOK)
      return false;

    // Reject differing bases from the normal codepath; we special-case
    // comparisons to null.
    if (!HasSameBase(LHSValue, RHSValue)) {
      // Handle &&A - &&B.
      if (!LHSValue.Offset.isZero() || !RHSValue.Offset.isZero())
        return Error(E);
      const Expr *LHSExpr = LHSValue.Base.dyn_cast<const Expr *>();
      const Expr *RHSExpr = RHSValue.Base.dyn_cast<const Expr *>();
      if (!LHSExpr || !RHSExpr)
        return Error(E);
      const AddrLabelExpr *LHSAddrExpr = dyn_cast<AddrLabelExpr>(LHSExpr);
      const AddrLabelExpr *RHSAddrExpr = dyn_cast<AddrLabelExpr>(RHSExpr);
      if (!LHSAddrExpr || !RHSAddrExpr)
        return Error(E);
      // Make sure both labels come from the same function.
      if (LHSAddrExpr->getLabel()->getDeclContext() !=
          RHSAddrExpr->getLabel()->getDeclContext())
        return Error(E);
      return Success(APValue(LHSAddrExpr, RHSAddrExpr), E);
    }
    const CharUnits &LHSOffset = LHSValue.getLValueOffset();
    const CharUnits &RHSOffset = RHSValue.getLValueOffset();

    SubobjectDesignator &LHSDesignator = LHSValue.getLValueDesignator();
    SubobjectDesignator &RHSDesignator = RHSValue.getLValueDesignator();

    // C++11 [expr.add]p6:
    //   Unless both pointers point to elements of the same array object, or
    //   one past the last element of the array object, the behavior is
    //   undefined.
    if (!LHSDesignator.Invalid && !RHSDesignator.Invalid &&
        !AreElementsOfSameArray(getType(LHSValue.Base), LHSDesignator,
                                RHSDesignator))
      Info.CCEDiag(E, diag::note_constexpr_pointer_subtraction_not_same_array);

    QualType Type = E->getLHS()->getType();
    QualType ElementType = Type->castAs<PointerType>()->getPointeeType();

    CharUnits ElementSize;
    if (!HandleSizeof(Info, E->getExprLoc(), ElementType, ElementSize))
      return false;

    // As an extension, a type may have zero size (empty struct or union in
    // C, array of zero length). Pointer subtraction in such cases has
    // undefined behavior, so is not constant.
    if (ElementSize.isZero()) {
      Info.FFDiag(E, diag::note_constexpr_pointer_subtraction_zero_size)
          << ElementType;
      return false;
    }

    // FIXME: LLVM and GCC both compute LHSOffset - RHSOffset at runtime,
    // and produce incorrect results when it overflows. Such behavior
    // appears to be non-conforming, but is common, so perhaps we should
    // assume the standard intended for such cases to be undefined behavior
    // and check for them.

    // Compute (LHSOffset - RHSOffset) / Size carefully, checking for
    // overflow in the final conversion to ptrdiff_t.
    APSInt LHS(llvm::APInt(65, (int64_t)LHSOffset.getQuantity(), true), false);
    APSInt RHS(llvm::APInt(65, (int64_t)RHSOffset.getQuantity(), true), false);
    APSInt ElemSize(llvm::APInt(65, (int64_t)ElementSize.getQuantity(), true),
                    false);
    APSInt TrueResult = (LHS - RHS) / ElemSize;
    APSInt Result = TrueResult.trunc(Info.Ctx.getIntWidth(E->getType()));

    if (Result.extend(65) != TrueResult &&
        !HandleOverflow(Info, E, TrueResult, E->getType()))
      return false;
    return Success(Result, E);
  }

  return ExprEvaluatorBaseTy::VisitBinaryOperator(E);
}

/// VisitUnaryExprOrTypeTraitExpr - Evaluate a sizeof, alignof or vec_step with
/// a result as the expression's type.
bool IntExprEvaluator::VisitUnaryExprOrTypeTraitExpr(
                                    const UnaryExprOrTypeTraitExpr *E) {
  switch(E->getKind()) {
  case UETT_PreferredAlignOf:
  case UETT_AlignOf: {
    if (E->isArgumentType())
      return Success(GetAlignOfType(Info, E->getArgumentType(), E->getKind()),
                     E);
    else
      return Success(GetAlignOfExpr(Info, E->getArgumentExpr(), E->getKind()),
                     E);
  }

  case UETT_VecStep: {
    QualType Ty = E->getTypeOfArgument();

    if (Ty->isVectorType()) {
      unsigned n = Ty->castAs<VectorType>()->getNumElements();

      // The vec_step built-in functions that take a 3-component
      // vector return 4. (OpenCL 1.1 spec 6.11.12)
      if (n == 3)
        n = 4;

      return Success(n, E);
    } else
      return Success(1, E);
  }

  case UETT_SizeOf: {
    QualType SrcTy = E->getTypeOfArgument();
    // C++ [expr.sizeof]p2: "When applied to a reference or a reference type,
    //   the result is the size of the referenced type."
    if (const ReferenceType *Ref = SrcTy->getAs<ReferenceType>())
      SrcTy = Ref->getPointeeType();

    CharUnits Sizeof;
    if (!HandleSizeof(Info, E->getExprLoc(), SrcTy, Sizeof))
      return false;
    return Success(Sizeof, E);
  }
  case UETT_OpenMPRequiredSimdAlign:
    assert(E->isArgumentType());
    return Success(
        Info.Ctx.toCharUnitsFromBits(
                    Info.Ctx.getOpenMPDefaultSimdAlign(E->getArgumentType()))
            .getQuantity(),
        E);
  }

  llvm_unreachable("unknown expr/type trait");
}

bool IntExprEvaluator::VisitOffsetOfExpr(const OffsetOfExpr *OOE) {
  CharUnits Result;
  unsigned n = OOE->getNumComponents();
  if (n == 0)
    return Error(OOE);
  QualType CurrentType = OOE->getTypeSourceInfo()->getType();
  for (unsigned i = 0; i != n; ++i) {
    OffsetOfNode ON = OOE->getComponent(i);
    switch (ON.getKind()) {
    case OffsetOfNode::Array: {
      const Expr *Idx = OOE->getIndexExpr(ON.getArrayExprIndex());
      APSInt IdxResult;
      if (!EvaluateInteger(Idx, IdxResult, Info))
        return false;
      const ArrayType *AT = Info.Ctx.getAsArrayType(CurrentType);
      if (!AT)
        return Error(OOE);
      CurrentType = AT->getElementType();
      CharUnits ElementSize = Info.Ctx.getTypeSizeInChars(CurrentType);
      Result += IdxResult.getSExtValue() * ElementSize;
      break;
    }

    case OffsetOfNode::Field: {
      FieldDecl *MemberDecl = ON.getField();
      const RecordType *RT = CurrentType->getAs<RecordType>();
      if (!RT)
        return Error(OOE);
      RecordDecl *RD = RT->getDecl();
      if (RD->isInvalidDecl()) return false;
      const ASTRecordLayout &RL = Info.Ctx.getASTRecordLayout(RD);
      unsigned i = MemberDecl->getFieldIndex();
      assert(i < RL.getFieldCount() && "offsetof field in wrong type");
      Result += Info.Ctx.toCharUnitsFromBits(RL.getFieldOffset(i));
      CurrentType = MemberDecl->getType().getNonReferenceType();
      break;
    }

    case OffsetOfNode::Identifier:
      llvm_unreachable("dependent __builtin_offsetof");

    case OffsetOfNode::Base: {
      CXXBaseSpecifier *BaseSpec = ON.getBase();
      if (BaseSpec->isVirtual())
        return Error(OOE);

      // Find the layout of the class whose base we are looking into.
      const RecordType *RT = CurrentType->getAs<RecordType>();
      if (!RT)
        return Error(OOE);
      RecordDecl *RD = RT->getDecl();
      if (RD->isInvalidDecl()) return false;
      const ASTRecordLayout &RL = Info.Ctx.getASTRecordLayout(RD);

      // Find the base class itself.
      CurrentType = BaseSpec->getType();
      const RecordType *BaseRT = CurrentType->getAs<RecordType>();
      if (!BaseRT)
        return Error(OOE);

      // Add the offset to the base.
      Result += RL.getBaseClassOffset(cast<CXXRecordDecl>(BaseRT->getDecl()));
      break;
    }
    }
  }
  return Success(Result, OOE);
}

bool IntExprEvaluator::VisitUnaryOperator(const UnaryOperator *E) {
  switch (E->getOpcode()) {
  default:
    // Address, indirect, pre/post inc/dec, etc are not valid constant exprs.
    // See C99 6.6p3.
    return Error(E);
  case UO_Extension:
    // FIXME: Should extension allow i-c-e extension expressions in its scope?
    // If so, we could clear the diagnostic ID.
    return Visit(E->getSubExpr());
  case UO_Plus:
    // The result is just the value.
    return Visit(E->getSubExpr());
  case UO_Minus: {
    if (!Visit(E->getSubExpr()))
      return false;
    if (!Result.isInt()) return Error(E);
    const APSInt &Value = Result.getInt();
    if (Value.isSigned() && Value.isMinSignedValue() && E->canOverflow() &&
        !HandleOverflow(Info, E, -Value.extend(Value.getBitWidth() + 1),
                        E->getType()))
      return false;
    return Success(-Value, E);
  }
  case UO_Not: {
    if (!Visit(E->getSubExpr()))
      return false;
    if (!Result.isInt()) return Error(E);
    return Success(~Result.getInt(), E);
  }
  case UO_LNot: {
    bool bres;
    if (!EvaluateAsBooleanCondition(E->getSubExpr(), bres, Info))
      return false;
    return Success(!bres, E);
  }
  }
}

/// HandleCast - This is used to evaluate implicit or explicit casts where the
/// result type is integer.
bool IntExprEvaluator::VisitCastExpr(const CastExpr *E) {
  const Expr *SubExpr = E->getSubExpr();
  QualType DestType = E->getType();
  QualType SrcType = SubExpr->getType();

  switch (E->getCastKind()) {
  case CK_BaseToDerived:
  case CK_DerivedToBase:
  case CK_UncheckedDerivedToBase:
  case CK_Dynamic:
  case CK_ToUnion:
  case CK_ArrayToPointerDecay:
  case CK_FunctionToPointerDecay:
  case CK_NullToPointer:
  case CK_NullToMemberPointer:
  case CK_BaseToDerivedMemberPointer:
  case CK_DerivedToBaseMemberPointer:
  case CK_ReinterpretMemberPointer:
  case CK_ConstructorConversion:
  case CK_IntegralToPointer:
  case CK_ToVoid:
  case CK_VectorSplat:
  case CK_IntegralToFloating:
  case CK_FloatingCast:
  case CK_CPointerToObjCPointerCast:
  case CK_BlockPointerToObjCPointerCast:
  case CK_AnyPointerToBlockPointerCast:
  case CK_ObjCObjectLValueCast:
  case CK_FloatingRealToComplex:
  case CK_FloatingComplexToReal:
  case CK_FloatingComplexCast:
  case CK_FloatingComplexToIntegralComplex:
  case CK_IntegralRealToComplex:
  case CK_IntegralComplexCast:
  case CK_IntegralComplexToFloatingComplex:
  case CK_BuiltinFnToFnPtr:
  case CK_ZeroToOCLOpaqueType:
  case CK_NonAtomicToAtomic:
  case CK_AddressSpaceConversion:
  case CK_IntToOCLSampler:
  case CK_FixedPointCast:
  case CK_IntegralToFixedPoint:
    llvm_unreachable("invalid cast kind for integral value");

  case CK_BitCast:
  case CK_Dependent:
  case CK_LValueBitCast:
  case CK_ARCProduceObject:
  case CK_ARCConsumeObject:
  case CK_ARCReclaimReturnedObject:
  case CK_ARCExtendBlockObject:
  case CK_CopyAndAutoreleaseBlockObject:
    return Error(E);

  case CK_UserDefinedConversion:
  case CK_LValueToRValue:
  case CK_AtomicToNonAtomic:
  case CK_NoOp:
  case CK_LValueToRValueBitCast:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);

  case CK_MemberPointerToBoolean:
  case CK_PointerToBoolean:
  case CK_IntegralToBoolean:
  case CK_FloatingToBoolean:
  case CK_BooleanToSignedIntegral:
  case CK_FloatingComplexToBoolean:
  case CK_IntegralComplexToBoolean: {
    bool BoolResult;
    if (!EvaluateAsBooleanCondition(SubExpr, BoolResult, Info))
      return false;
    uint64_t IntResult = BoolResult;
    if (BoolResult && E->getCastKind() == CK_BooleanToSignedIntegral)
      IntResult = (uint64_t)-1;
    return Success(IntResult, E);
  }

  case CK_FixedPointToIntegral: {
    APFixedPoint Src(Info.Ctx.getFixedPointSemantics(SrcType));
    if (!EvaluateFixedPoint(SubExpr, Src, Info))
      return false;
    bool Overflowed;
    llvm::APSInt Result = Src.convertToInt(
        Info.Ctx.getIntWidth(DestType),
        DestType->isSignedIntegerOrEnumerationType(), &Overflowed);
    if (Overflowed && !HandleOverflow(Info, E, Result, DestType))
      return false;
    return Success(Result, E);
  }

  case CK_FixedPointToBoolean: {
    // Unsigned padding does not affect this.
    APValue Val;
    if (!Evaluate(Val, Info, SubExpr))
      return false;
    return Success(Val.getFixedPoint().getBoolValue(), E);
  }

  case CK_IntegralCast: {
    if (!Visit(SubExpr))
      return false;

    if (!Result.isInt()) {
      // Allow casts of address-of-label differences if they are no-ops
      // or narrowing.  (The narrowing case isn't actually guaranteed to
      // be constant-evaluatable except in some narrow cases which are hard
      // to detect here.  We let it through on the assumption the user knows
      // what they are doing.)
      if (Result.isAddrLabelDiff())
        return Info.Ctx.getTypeSize(DestType) <= Info.Ctx.getTypeSize(SrcType);
      // Only allow casts of lvalues if they are lossless.
      return Info.Ctx.getTypeSize(DestType) == Info.Ctx.getTypeSize(SrcType);
    }

    return Success(HandleIntToIntCast(Info, E, DestType, SrcType,
                                      Result.getInt()), E);
  }

  case CK_PointerToIntegral: {
    CCEDiag(E, diag::note_constexpr_invalid_cast) << 2;

    LValue LV;
    if (!EvaluatePointer(SubExpr, LV, Info))
      return false;

    if (LV.getLValueBase()) {
      // Only allow based lvalue casts if they are lossless.
      // FIXME: Allow a larger integer size than the pointer size, and allow
      // narrowing back down to pointer width in subsequent integral casts.
      // FIXME: Check integer type's active bits, not its type size.
      if (Info.Ctx.getTypeSize(DestType) != Info.Ctx.getTypeSize(SrcType))
        return Error(E);

      LV.Designator.setInvalid();
      LV.moveInto(Result);
      return true;
    }

    APSInt AsInt;
    APValue V;
    LV.moveInto(V);
    if (!V.toIntegralConstant(AsInt, SrcType, Info.Ctx))
      llvm_unreachable("Can't cast this!");

    return Success(HandleIntToIntCast(Info, E, DestType, SrcType, AsInt), E);
  }

  case CK_IntegralComplexToReal: {
    ComplexValue C;
    if (!EvaluateComplex(SubExpr, C, Info))
      return false;
    return Success(C.getComplexIntReal(), E);
  }

  case CK_FloatingToIntegral: {
    APFloat F(0.0);
    if (!EvaluateFloat(SubExpr, F, Info))
      return false;

    APSInt Value;
    if (!HandleFloatToIntCast(Info, E, SrcType, F, DestType, Value))
      return false;
    return Success(Value, E);
  }
  }

  llvm_unreachable("unknown cast resulting in integral value");
}

bool IntExprEvaluator::VisitUnaryReal(const UnaryOperator *E) {
  if (E->getSubExpr()->getType()->isAnyComplexType()) {
    ComplexValue LV;
    if (!EvaluateComplex(E->getSubExpr(), LV, Info))
      return false;
    if (!LV.isComplexInt())
      return Error(E);
    return Success(LV.getComplexIntReal(), E);
  }

  return Visit(E->getSubExpr());
}

bool IntExprEvaluator::VisitUnaryImag(const UnaryOperator *E) {
  if (E->getSubExpr()->getType()->isComplexIntegerType()) {
    ComplexValue LV;
    if (!EvaluateComplex(E->getSubExpr(), LV, Info))
      return false;
    if (!LV.isComplexInt())
      return Error(E);
    return Success(LV.getComplexIntImag(), E);
  }

  VisitIgnoredValue(E->getSubExpr());
  return Success(0, E);
}

bool IntExprEvaluator::VisitSizeOfPackExpr(const SizeOfPackExpr *E) {
  return Success(E->getPackLength(), E);
}

bool IntExprEvaluator::VisitCXXNoexceptExpr(const CXXNoexceptExpr *E) {
  return Success(E->getValue(), E);
}

bool IntExprEvaluator::VisitConceptSpecializationExpr(
       const ConceptSpecializationExpr *E) {
  return Success(E->isSatisfied(), E);
}

bool IntExprEvaluator::VisitRequiresExpr(const RequiresExpr *E) {
  return Success(E->isSatisfied(), E);
}

bool FixedPointExprEvaluator::VisitUnaryOperator(const UnaryOperator *E) {
  switch (E->getOpcode()) {
    default:
      // Invalid unary operators
      return Error(E);
    case UO_Plus:
      // The result is just the value.
      return Visit(E->getSubExpr());
    case UO_Minus: {
      if (!Visit(E->getSubExpr())) return false;
      if (!Result.isFixedPoint())
        return Error(E);
      bool Overflowed;
      APFixedPoint Negated = Result.getFixedPoint().negate(&Overflowed);
      if (Overflowed && !HandleOverflow(Info, E, Negated, E->getType()))
        return false;
      return Success(Negated, E);
    }
    case UO_LNot: {
      bool bres;
      if (!EvaluateAsBooleanCondition(E->getSubExpr(), bres, Info))
        return false;
      return Success(!bres, E);
    }
  }
}

bool FixedPointExprEvaluator::VisitCastExpr(const CastExpr *E) {
  const Expr *SubExpr = E->getSubExpr();
  QualType DestType = E->getType();
  assert(DestType->isFixedPointType() &&
         "Expected destination type to be a fixed point type");
  auto DestFXSema = Info.Ctx.getFixedPointSemantics(DestType);

  switch (E->getCastKind()) {
  case CK_FixedPointCast: {
    APFixedPoint Src(Info.Ctx.getFixedPointSemantics(SubExpr->getType()));
    if (!EvaluateFixedPoint(SubExpr, Src, Info))
      return false;
    bool Overflowed;
    APFixedPoint Result = Src.convert(DestFXSema, &Overflowed);
    if (Overflowed && !HandleOverflow(Info, E, Result, DestType))
      return false;
    return Success(Result, E);
  }
  case CK_IntegralToFixedPoint: {
    APSInt Src;
    if (!EvaluateInteger(SubExpr, Src, Info))
      return false;

    bool Overflowed;
    APFixedPoint IntResult = APFixedPoint::getFromIntValue(
        Src, Info.Ctx.getFixedPointSemantics(DestType), &Overflowed);

    if (Overflowed && !HandleOverflow(Info, E, IntResult, DestType))
      return false;

    return Success(IntResult, E);
  }
  case CK_NoOp:
  case CK_LValueToRValue:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);
  default:
    return Error(E);
  }
}

bool FixedPointExprEvaluator::VisitBinaryOperator(const BinaryOperator *E) {
  const Expr *LHS = E->getLHS();
  const Expr *RHS = E->getRHS();
  FixedPointSemantics ResultFXSema =
      Info.Ctx.getFixedPointSemantics(E->getType());

  APFixedPoint LHSFX(Info.Ctx.getFixedPointSemantics(LHS->getType()));
  if (!EvaluateFixedPointOrInteger(LHS, LHSFX, Info))
    return false;
  APFixedPoint RHSFX(Info.Ctx.getFixedPointSemantics(RHS->getType()));
  if (!EvaluateFixedPointOrInteger(RHS, RHSFX, Info))
    return false;

  switch (E->getOpcode()) {
  case BO_Add: {
    bool AddOverflow, ConversionOverflow;
    APFixedPoint Result = LHSFX.add(RHSFX, &AddOverflow)
                              .convert(ResultFXSema, &ConversionOverflow);
    if ((AddOverflow || ConversionOverflow) &&
        !HandleOverflow(Info, E, Result, E->getType()))
      return false;
    return Success(Result, E);
  }
  default:
    return false;
  }
  llvm_unreachable("Should've exited before this");
}

//===----------------------------------------------------------------------===//
// Float Evaluation
//===----------------------------------------------------------------------===//

namespace {
class FloatExprEvaluator
  : public ExprEvaluatorBase<FloatExprEvaluator> {
  APFloat &Result;
public:
  FloatExprEvaluator(EvalInfo &info, APFloat &result)
    : ExprEvaluatorBaseTy(info), Result(result) {}

  bool Success(const APValue &V, const Expr *e) {
    Result = V.getFloat();
    return true;
  }

  bool ZeroInitialization(const Expr *E) {
    Result = APFloat::getZero(Info.Ctx.getFloatTypeSemantics(E->getType()));
    return true;
  }

  bool VisitCallExpr(const CallExpr *E);

  bool VisitUnaryOperator(const UnaryOperator *E);
  bool VisitBinaryOperator(const BinaryOperator *E);
  bool VisitFloatingLiteral(const FloatingLiteral *E);
  bool VisitCastExpr(const CastExpr *E);

  bool VisitUnaryReal(const UnaryOperator *E);
  bool VisitUnaryImag(const UnaryOperator *E);

  // FIXME: Missing: array subscript of vector, member of vector
};
} // end anonymous namespace

static bool EvaluateFloat(const Expr* E, APFloat& Result, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isRealFloatingType());
  return FloatExprEvaluator(Info, Result).Visit(E);
}

static bool TryEvaluateBuiltinNaN(const ASTContext &Context,
                                  QualType ResultTy,
                                  const Expr *Arg,
                                  bool SNaN,
                                  llvm::APFloat &Result) {
  const StringLiteral *S = dyn_cast<StringLiteral>(Arg->IgnoreParenCasts());
  if (!S) return false;

  const llvm::fltSemantics &Sem = Context.getFloatTypeSemantics(ResultTy);

  llvm::APInt fill;

  // Treat empty strings as if they were zero.
  if (S->getString().empty())
    fill = llvm::APInt(32, 0);
  else if (S->getString().getAsInteger(0, fill))
    return false;

  if (Context.getTargetInfo().isNan2008()) {
    if (SNaN)
      Result = llvm::APFloat::getSNaN(Sem, false, &fill);
    else
      Result = llvm::APFloat::getQNaN(Sem, false, &fill);
  } else {
    // Prior to IEEE 754-2008, architectures were allowed to choose whether
    // the first bit of their significand was set for qNaN or sNaN. MIPS chose
    // a different encoding to what became a standard in 2008, and for pre-
    // 2008 revisions, MIPS interpreted sNaN-2008 as qNan and qNaN-2008 as
    // sNaN. This is now known as "legacy NaN" encoding.
    if (SNaN)
      Result = llvm::APFloat::getQNaN(Sem, false, &fill);
    else
      Result = llvm::APFloat::getSNaN(Sem, false, &fill);
  }

  return true;
}

bool FloatExprEvaluator::VisitCallExpr(const CallExpr *E) {
  switch (E->getBuiltinCallee()) {
  default:
    return ExprEvaluatorBaseTy::VisitCallExpr(E);

  case Builtin::BI__builtin_huge_val:
  case Builtin::BI__builtin_huge_valf:
  case Builtin::BI__builtin_huge_vall:
  case Builtin::BI__builtin_huge_valf128:
  case Builtin::BI__builtin_inf:
  case Builtin::BI__builtin_inff:
  case Builtin::BI__builtin_infl:
  case Builtin::BI__builtin_inff128: {
    const llvm::fltSemantics &Sem =
      Info.Ctx.getFloatTypeSemantics(E->getType());
    Result = llvm::APFloat::getInf(Sem);
    return true;
  }

  case Builtin::BI__builtin_nans:
  case Builtin::BI__builtin_nansf:
  case Builtin::BI__builtin_nansl:
  case Builtin::BI__builtin_nansf128:
    if (!TryEvaluateBuiltinNaN(Info.Ctx, E->getType(), E->getArg(0),
                               true, Result))
      return Error(E);
    return true;

  case Builtin::BI__builtin_nan:
  case Builtin::BI__builtin_nanf:
  case Builtin::BI__builtin_nanl:
  case Builtin::BI__builtin_nanf128:
    // If this is __builtin_nan() turn this into a nan, otherwise we
    // can't constant fold it.
    if (!TryEvaluateBuiltinNaN(Info.Ctx, E->getType(), E->getArg(0),
                               false, Result))
      return Error(E);
    return true;

  case Builtin::BI__builtin_fabs:
  case Builtin::BI__builtin_fabsf:
  case Builtin::BI__builtin_fabsl:
  case Builtin::BI__builtin_fabsf128:
    if (!EvaluateFloat(E->getArg(0), Result, Info))
      return false;

    if (Result.isNegative())
      Result.changeSign();
    return true;

  // FIXME: Builtin::BI__builtin_powi
  // FIXME: Builtin::BI__builtin_powif
  // FIXME: Builtin::BI__builtin_powil

  case Builtin::BI__builtin_copysign:
  case Builtin::BI__builtin_copysignf:
  case Builtin::BI__builtin_copysignl:
  case Builtin::BI__builtin_copysignf128: {
    APFloat RHS(0.);
    if (!EvaluateFloat(E->getArg(0), Result, Info) ||
        !EvaluateFloat(E->getArg(1), RHS, Info))
      return false;
    Result.copySign(RHS);
    return true;
  }
  }
}

bool FloatExprEvaluator::VisitUnaryReal(const UnaryOperator *E) {
  if (E->getSubExpr()->getType()->isAnyComplexType()) {
    ComplexValue CV;
    if (!EvaluateComplex(E->getSubExpr(), CV, Info))
      return false;
    Result = CV.FloatReal;
    return true;
  }

  return Visit(E->getSubExpr());
}

bool FloatExprEvaluator::VisitUnaryImag(const UnaryOperator *E) {
  if (E->getSubExpr()->getType()->isAnyComplexType()) {
    ComplexValue CV;
    if (!EvaluateComplex(E->getSubExpr(), CV, Info))
      return false;
    Result = CV.FloatImag;
    return true;
  }

  VisitIgnoredValue(E->getSubExpr());
  const llvm::fltSemantics &Sem = Info.Ctx.getFloatTypeSemantics(E->getType());
  Result = llvm::APFloat::getZero(Sem);
  return true;
}

bool FloatExprEvaluator::VisitUnaryOperator(const UnaryOperator *E) {
  switch (E->getOpcode()) {
  default: return Error(E);
  case UO_Plus:
    return EvaluateFloat(E->getSubExpr(), Result, Info);
  case UO_Minus:
    if (!EvaluateFloat(E->getSubExpr(), Result, Info))
      return false;
    Result.changeSign();
    return true;
  }
}

bool FloatExprEvaluator::VisitBinaryOperator(const BinaryOperator *E) {
  if (E->isPtrMemOp() || E->isAssignmentOp() || E->getOpcode() == BO_Comma)
    return ExprEvaluatorBaseTy::VisitBinaryOperator(E);

  APFloat RHS(0.0);
  bool LHSOK = EvaluateFloat(E->getLHS(), Result, Info);
  if (!LHSOK && !Info.noteFailure())
    return false;
  return EvaluateFloat(E->getRHS(), RHS, Info) && LHSOK &&
         handleFloatFloatBinOp(Info, E, Result, E->getOpcode(), RHS);
}

bool FloatExprEvaluator::VisitFloatingLiteral(const FloatingLiteral *E) {
  Result = E->getValue();
  return true;
}

bool FloatExprEvaluator::VisitCastExpr(const CastExpr *E) {
  const Expr* SubExpr = E->getSubExpr();

  switch (E->getCastKind()) {
  default:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);

  case CK_IntegralToFloating: {
    APSInt IntResult;
    return EvaluateInteger(SubExpr, IntResult, Info) &&
           HandleIntToFloatCast(Info, E, SubExpr->getType(), IntResult,
                                E->getType(), Result);
  }

  case CK_FloatingCast: {
    if (!Visit(SubExpr))
      return false;
    return HandleFloatToFloatCast(Info, E, SubExpr->getType(), E->getType(),
                                  Result);
  }

  case CK_FloatingComplexToReal: {
    ComplexValue V;
    if (!EvaluateComplex(SubExpr, V, Info))
      return false;
    Result = V.getComplexFloatReal();
    return true;
  }
  }
}

//===----------------------------------------------------------------------===//
// Complex Evaluation (for float and integer)
//===----------------------------------------------------------------------===//

namespace {
class ComplexExprEvaluator
  : public ExprEvaluatorBase<ComplexExprEvaluator> {
  ComplexValue &Result;

public:
  ComplexExprEvaluator(EvalInfo &info, ComplexValue &Result)
    : ExprEvaluatorBaseTy(info), Result(Result) {}

  bool Success(const APValue &V, const Expr *e) {
    Result.setFrom(V);
    return true;
  }

  bool ZeroInitialization(const Expr *E);

  //===--------------------------------------------------------------------===//
  //                            Visitor Methods
  //===--------------------------------------------------------------------===//

  bool VisitImaginaryLiteral(const ImaginaryLiteral *E);
  bool VisitCastExpr(const CastExpr *E);
  bool VisitBinaryOperator(const BinaryOperator *E);
  bool VisitUnaryOperator(const UnaryOperator *E);
  bool VisitInitListExpr(const InitListExpr *E);
};
} // end anonymous namespace

static bool EvaluateComplex(const Expr *E, ComplexValue &Result,
                            EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isAnyComplexType());
  return ComplexExprEvaluator(Info, Result).Visit(E);
}

bool ComplexExprEvaluator::ZeroInitialization(const Expr *E) {
  QualType ElemTy = E->getType()->castAs<ComplexType>()->getElementType();
  if (ElemTy->isRealFloatingType()) {
    Result.makeComplexFloat();
    APFloat Zero = APFloat::getZero(Info.Ctx.getFloatTypeSemantics(ElemTy));
    Result.FloatReal = Zero;
    Result.FloatImag = Zero;
  } else {
    Result.makeComplexInt();
    APSInt Zero = Info.Ctx.MakeIntValue(0, ElemTy);
    Result.IntReal = Zero;
    Result.IntImag = Zero;
  }
  return true;
}

bool ComplexExprEvaluator::VisitImaginaryLiteral(const ImaginaryLiteral *E) {
  const Expr* SubExpr = E->getSubExpr();

  if (SubExpr->getType()->isRealFloatingType()) {
    Result.makeComplexFloat();
    APFloat &Imag = Result.FloatImag;
    if (!EvaluateFloat(SubExpr, Imag, Info))
      return false;

    Result.FloatReal = APFloat(Imag.getSemantics());
    return true;
  } else {
    assert(SubExpr->getType()->isIntegerType() &&
           "Unexpected imaginary literal.");

    Result.makeComplexInt();
    APSInt &Imag = Result.IntImag;
    if (!EvaluateInteger(SubExpr, Imag, Info))
      return false;

    Result.IntReal = APSInt(Imag.getBitWidth(), !Imag.isSigned());
    return true;
  }
}

bool ComplexExprEvaluator::VisitCastExpr(const CastExpr *E) {

  switch (E->getCastKind()) {
  case CK_BitCast:
  case CK_BaseToDerived:
  case CK_DerivedToBase:
  case CK_UncheckedDerivedToBase:
  case CK_Dynamic:
  case CK_ToUnion:
  case CK_ArrayToPointerDecay:
  case CK_FunctionToPointerDecay:
  case CK_NullToPointer:
  case CK_NullToMemberPointer:
  case CK_BaseToDerivedMemberPointer:
  case CK_DerivedToBaseMemberPointer:
  case CK_MemberPointerToBoolean:
  case CK_ReinterpretMemberPointer:
  case CK_ConstructorConversion:
  case CK_IntegralToPointer:
  case CK_PointerToIntegral:
  case CK_PointerToBoolean:
  case CK_ToVoid:
  case CK_VectorSplat:
  case CK_IntegralCast:
  case CK_BooleanToSignedIntegral:
  case CK_IntegralToBoolean:
  case CK_IntegralToFloating:
  case CK_FloatingToIntegral:
  case CK_FloatingToBoolean:
  case CK_FloatingCast:
  case CK_CPointerToObjCPointerCast:
  case CK_BlockPointerToObjCPointerCast:
  case CK_AnyPointerToBlockPointerCast:
  case CK_ObjCObjectLValueCast:
  case CK_FloatingComplexToReal:
  case CK_FloatingComplexToBoolean:
  case CK_IntegralComplexToReal:
  case CK_IntegralComplexToBoolean:
  case CK_ARCProduceObject:
  case CK_ARCConsumeObject:
  case CK_ARCReclaimReturnedObject:
  case CK_ARCExtendBlockObject:
  case CK_CopyAndAutoreleaseBlockObject:
  case CK_BuiltinFnToFnPtr:
  case CK_ZeroToOCLOpaqueType:
  case CK_NonAtomicToAtomic:
  case CK_AddressSpaceConversion:
  case CK_IntToOCLSampler:
  case CK_FixedPointCast:
  case CK_FixedPointToBoolean:
  case CK_FixedPointToIntegral:
  case CK_IntegralToFixedPoint:
    llvm_unreachable("invalid cast kind for complex value");

  case CK_LValueToRValue:
  case CK_AtomicToNonAtomic:
  case CK_NoOp:
  case CK_LValueToRValueBitCast:
    return ExprEvaluatorBaseTy::VisitCastExpr(E);

  case CK_Dependent:
  case CK_LValueBitCast:
  case CK_UserDefinedConversion:
    return Error(E);

  case CK_FloatingRealToComplex: {
    APFloat &Real = Result.FloatReal;
    if (!EvaluateFloat(E->getSubExpr(), Real, Info))
      return false;

    Result.makeComplexFloat();
    Result.FloatImag = APFloat(Real.getSemantics());
    return true;
  }

  case CK_FloatingComplexCast: {
    if (!Visit(E->getSubExpr()))
      return false;

    QualType To = E->getType()->castAs<ComplexType>()->getElementType();
    QualType From
      = E->getSubExpr()->getType()->castAs<ComplexType>()->getElementType();

    return HandleFloatToFloatCast(Info, E, From, To, Result.FloatReal) &&
           HandleFloatToFloatCast(Info, E, From, To, Result.FloatImag);
  }

  case CK_FloatingComplexToIntegralComplex: {
    if (!Visit(E->getSubExpr()))
      return false;

    QualType To = E->getType()->castAs<ComplexType>()->getElementType();
    QualType From
      = E->getSubExpr()->getType()->castAs<ComplexType>()->getElementType();
    Result.makeComplexInt();
    return HandleFloatToIntCast(Info, E, From, Result.FloatReal,
                                To, Result.IntReal) &&
           HandleFloatToIntCast(Info, E, From, Result.FloatImag,
                                To, Result.IntImag);
  }

  case CK_IntegralRealToComplex: {
    APSInt &Real = Result.IntReal;
    if (!EvaluateInteger(E->getSubExpr(), Real, Info))
      return false;

    Result.makeComplexInt();
    Result.IntImag = APSInt(Real.getBitWidth(), !Real.isSigned());
    return true;
  }

  case CK_IntegralComplexCast: {
    if (!Visit(E->getSubExpr()))
      return false;

    QualType To = E->getType()->castAs<ComplexType>()->getElementType();
    QualType From
      = E->getSubExpr()->getType()->castAs<ComplexType>()->getElementType();

    Result.IntReal = HandleIntToIntCast(Info, E, To, From, Result.IntReal);
    Result.IntImag = HandleIntToIntCast(Info, E, To, From, Result.IntImag);
    return true;
  }

  case CK_IntegralComplexToFloatingComplex: {
    if (!Visit(E->getSubExpr()))
      return false;

    QualType To = E->getType()->castAs<ComplexType>()->getElementType();
    QualType From
      = E->getSubExpr()->getType()->castAs<ComplexType>()->getElementType();
    Result.makeComplexFloat();
    return HandleIntToFloatCast(Info, E, From, Result.IntReal,
                                To, Result.FloatReal) &&
           HandleIntToFloatCast(Info, E, From, Result.IntImag,
                                To, Result.FloatImag);
  }
  }

  llvm_unreachable("unknown cast resulting in complex value");
}

bool ComplexExprEvaluator::VisitBinaryOperator(const BinaryOperator *E) {
  if (E->isPtrMemOp() || E->isAssignmentOp() || E->getOpcode() == BO_Comma)
    return ExprEvaluatorBaseTy::VisitBinaryOperator(E);

  // Track whether the LHS or RHS is real at the type system level. When this is
  // the case we can simplify our evaluation strategy.
  bool LHSReal = false, RHSReal = false;

  bool LHSOK;
  if (E->getLHS()->getType()->isRealFloatingType()) {
    LHSReal = true;
    APFloat &Real = Result.FloatReal;
    LHSOK = EvaluateFloat(E->getLHS(), Real, Info);
    if (LHSOK) {
      Result.makeComplexFloat();
      Result.FloatImag = APFloat(Real.getSemantics());
    }
  } else {
    LHSOK = Visit(E->getLHS());
  }
  if (!LHSOK && !Info.noteFailure())
    return false;

  ComplexValue RHS;
  if (E->getRHS()->getType()->isRealFloatingType()) {
    RHSReal = true;
    APFloat &Real = RHS.FloatReal;
    if (!EvaluateFloat(E->getRHS(), Real, Info) || !LHSOK)
      return false;
    RHS.makeComplexFloat();
    RHS.FloatImag = APFloat(Real.getSemantics());
  } else if (!EvaluateComplex(E->getRHS(), RHS, Info) || !LHSOK)
    return false;

  assert(!(LHSReal && RHSReal) &&
         "Cannot have both operands of a complex operation be real.");
  switch (E->getOpcode()) {
  default: return Error(E);
  case BO_Add:
    if (Result.isComplexFloat()) {
      Result.getComplexFloatReal().add(RHS.getComplexFloatReal(),
                                       APFloat::rmNearestTiesToEven);
      if (LHSReal)
        Result.getComplexFloatImag() = RHS.getComplexFloatImag();
      else if (!RHSReal)
        Result.getComplexFloatImag().add(RHS.getComplexFloatImag(),
                                         APFloat::rmNearestTiesToEven);
    } else {
      Result.getComplexIntReal() += RHS.getComplexIntReal();
      Result.getComplexIntImag() += RHS.getComplexIntImag();
    }
    break;
  case BO_Sub:
    if (Result.isComplexFloat()) {
      Result.getComplexFloatReal().subtract(RHS.getComplexFloatReal(),
                                            APFloat::rmNearestTiesToEven);
      if (LHSReal) {
        Result.getComplexFloatImag() = RHS.getComplexFloatImag();
        Result.getComplexFloatImag().changeSign();
      } else if (!RHSReal) {
        Result.getComplexFloatImag().subtract(RHS.getComplexFloatImag(),
                                              APFloat::rmNearestTiesToEven);
      }
    } else {
      Result.getComplexIntReal() -= RHS.getComplexIntReal();
      Result.getComplexIntImag() -= RHS.getComplexIntImag();
    }
    break;
  case BO_Mul:
    if (Result.isComplexFloat()) {
      // This is an implementation of complex multiplication according to the
      // constraints laid out in C11 Annex G. The implementation uses the
      // following naming scheme:
      //   (a + ib) * (c + id)
      ComplexValue LHS = Result;
      APFloat &A = LHS.getComplexFloatReal();
      APFloat &B = LHS.getComplexFloatImag();
      APFloat &C = RHS.getComplexFloatReal();
      APFloat &D = RHS.getComplexFloatImag();
      APFloat &ResR = Result.getComplexFloatReal();
      APFloat &ResI = Result.getComplexFloatImag();
      if (LHSReal) {
        assert(!RHSReal && "Cannot have two real operands for a complex op!");
        ResR = A * C;
        ResI = A * D;
      } else if (RHSReal) {
        ResR = C * A;
        ResI = C * B;
      } else {
        // In the fully general case, we need to handle NaNs and infinities
        // robustly.
        APFloat AC = A * C;
        APFloat BD = B * D;
        APFloat AD = A * D;
        APFloat BC = B * C;
        ResR = AC - BD;
        ResI = AD + BC;
        if (ResR.isNaN() && ResI.isNaN()) {
          bool Recalc = false;
          if (A.isInfinity() || B.isInfinity()) {
            A = APFloat::copySign(
                APFloat(A.getSemantics(), A.isInfinity() ? 1 : 0), A);
            B = APFloat::copySign(
                APFloat(B.getSemantics(), B.isInfinity() ? 1 : 0), B);
            if (C.isNaN())
              C = APFloat::copySign(APFloat(C.getSemantics()), C);
            if (D.isNaN())
              D = APFloat::copySign(APFloat(D.getSemantics()), D);
            Recalc = true;
          }
          if (C.isInfinity() || D.isInfinity()) {
            C = APFloat::copySign(
                APFloat(C.getSemantics(), C.isInfinity() ? 1 : 0), C);
            D = APFloat::copySign(
                APFloat(D.getSemantics(), D.isInfinity() ? 1 : 0), D);
            if (A.isNaN())
              A = APFloat::copySign(APFloat(A.getSemantics()), A);
            if (B.isNaN())
              B = APFloat::copySign(APFloat(B.getSemantics()), B);
            Recalc = true;
          }
          if (!Recalc && (AC.isInfinity() || BD.isInfinity() ||
                          AD.isInfinity() || BC.isInfinity())) {
            if (A.isNaN())
              A = APFloat::copySign(APFloat(A.getSemantics()), A);
            if (B.isNaN())
              B = APFloat::copySign(APFloat(B.getSemantics()), B);
            if (C.isNaN())
              C = APFloat::copySign(APFloat(C.getSemantics()), C);
            if (D.isNaN())
              D = APFloat::copySign(APFloat(D.getSemantics()), D);
            Recalc = true;
          }
          if (Recalc) {
            ResR = APFloat::getInf(A.getSemantics()) * (A * C - B * D);
            ResI = APFloat::getInf(A.getSemantics()) * (A * D + B * C);
          }
        }
      }
    } else {
      ComplexValue LHS = Result;
      Result.getComplexIntReal() =
        (LHS.getComplexIntReal() * RHS.getComplexIntReal() -
         LHS.getComplexIntImag() * RHS.getComplexIntImag());
      Result.getComplexIntImag() =
        (LHS.getComplexIntReal() * RHS.getComplexIntImag() +
         LHS.getComplexIntImag() * RHS.getComplexIntReal());
    }
    break;
  case BO_Div:
    if (Result.isComplexFloat()) {
      // This is an implementation of complex division according to the
      // constraints laid out in C11 Annex G. The implementation uses the
      // following naming scheme:
      //   (a + ib) / (c + id)
      ComplexValue LHS = Result;
      APFloat &A = LHS.getComplexFloatReal();
      APFloat &B = LHS.getComplexFloatImag();
      APFloat &C = RHS.getComplexFloatReal();
      APFloat &D = RHS.getComplexFloatImag();
      APFloat &ResR = Result.getComplexFloatReal();
      APFloat &ResI = Result.getComplexFloatImag();
      if (RHSReal) {
        ResR = A / C;
        ResI = B / C;
      } else {
        if (LHSReal) {
          // No real optimizations we can do here, stub out with zero.
          B = APFloat::getZero(A.getSemantics());
        }
        int DenomLogB = 0;
        APFloat MaxCD = maxnum(abs(C), abs(D));
        if (MaxCD.isFinite()) {
          DenomLogB = ilogb(MaxCD);
          C = scalbn(C, -DenomLogB, APFloat::rmNearestTiesToEven);
          D = scalbn(D, -DenomLogB, APFloat::rmNearestTiesToEven);
        }
        APFloat Denom = C * C + D * D;
        ResR = scalbn((A * C + B * D) / Denom, -DenomLogB,
                      APFloat::rmNearestTiesToEven);
        ResI = scalbn((B * C - A * D) / Denom, -DenomLogB,
                      APFloat::rmNearestTiesToEven);
        if (ResR.isNaN() && ResI.isNaN()) {
          if (Denom.isPosZero() && (!A.isNaN() || !B.isNaN())) {
            ResR = APFloat::getInf(ResR.getSemantics(), C.isNegative()) * A;
            ResI = APFloat::getInf(ResR.getSemantics(), C.isNegative()) * B;
          } else if ((A.isInfinity() || B.isInfinity()) && C.isFinite() &&
                     D.isFinite()) {
            A = APFloat::copySign(
                APFloat(A.getSemantics(), A.isInfinity() ? 1 : 0), A);
            B = APFloat::copySign(
                APFloat(B.getSemantics(), B.isInfinity() ? 1 : 0), B);
            ResR = APFloat::getInf(ResR.getSemantics()) * (A * C + B * D);
            ResI = APFloat::getInf(ResI.getSemantics()) * (B * C - A * D);
          } else if (MaxCD.isInfinity() && A.isFinite() && B.isFinite()) {
            C = APFloat::copySign(
                APFloat(C.getSemantics(), C.isInfinity() ? 1 : 0), C);
            D = APFloat::copySign(
                APFloat(D.getSemantics(), D.isInfinity() ? 1 : 0), D);
            ResR = APFloat::getZero(ResR.getSemantics()) * (A * C + B * D);
            ResI = APFloat::getZero(ResI.getSemantics()) * (B * C - A * D);
          }
        }
      }
    } else {
      if (RHS.getComplexIntReal() == 0 && RHS.getComplexIntImag() == 0)
        return Error(E, diag::note_expr_divide_by_zero);

      ComplexValue LHS = Result;
      APSInt Den = RHS.getComplexIntReal() * RHS.getComplexIntReal() +
        RHS.getComplexIntImag() * RHS.getComplexIntImag();
      Result.getComplexIntReal() =
        (LHS.getComplexIntReal() * RHS.getComplexIntReal() +
         LHS.getComplexIntImag() * RHS.getComplexIntImag()) / Den;
      Result.getComplexIntImag() =
        (LHS.getComplexIntImag() * RHS.getComplexIntReal() -
         LHS.getComplexIntReal() * RHS.getComplexIntImag()) / Den;
    }
    break;
  }

  return true;
}

bool ComplexExprEvaluator::VisitUnaryOperator(const UnaryOperator *E) {
  // Get the operand value into 'Result'.
  if (!Visit(E->getSubExpr()))
    return false;

  switch (E->getOpcode()) {
  default:
    return Error(E);
  case UO_Extension:
    return true;
  case UO_Plus:
    // The result is always just the subexpr.
    return true;
  case UO_Minus:
    if (Result.isComplexFloat()) {
      Result.getComplexFloatReal().changeSign();
      Result.getComplexFloatImag().changeSign();
    }
    else {
      Result.getComplexIntReal() = -Result.getComplexIntReal();
      Result.getComplexIntImag() = -Result.getComplexIntImag();
    }
    return true;
  case UO_Not:
    if (Result.isComplexFloat())
      Result.getComplexFloatImag().changeSign();
    else
      Result.getComplexIntImag() = -Result.getComplexIntImag();
    return true;
  }
}

bool ComplexExprEvaluator::VisitInitListExpr(const InitListExpr *E) {
  if (E->getNumInits() == 2) {
    if (E->getType()->isComplexType()) {
      Result.makeComplexFloat();
      if (!EvaluateFloat(E->getInit(0), Result.FloatReal, Info))
        return false;
      if (!EvaluateFloat(E->getInit(1), Result.FloatImag, Info))
        return false;
    } else {
      Result.makeComplexInt();
      if (!EvaluateInteger(E->getInit(0), Result.IntReal, Info))
        return false;
      if (!EvaluateInteger(E->getInit(1), Result.IntImag, Info))
        return false;
    }
    return true;
  }
  return ExprEvaluatorBaseTy::VisitInitListExpr(E);
}

//===----------------------------------------------------------------------===//
// Atomic expression evaluation, essentially just handling the NonAtomicToAtomic
// implicit conversion.
//===----------------------------------------------------------------------===//

namespace {
class AtomicExprEvaluator :
    public ExprEvaluatorBase<AtomicExprEvaluator> {
  const LValue *This;
  APValue &Result;
public:
  AtomicExprEvaluator(EvalInfo &Info, const LValue *This, APValue &Result)
      : ExprEvaluatorBaseTy(Info), This(This), Result(Result) {}

  bool Success(const APValue &V, const Expr *E) {
    Result = V;
    return true;
  }

  bool ZeroInitialization(const Expr *E) {
    ImplicitValueInitExpr VIE(
        E->getType()->castAs<AtomicType>()->getValueType());
    // For atomic-qualified class (and array) types in C++, initialize the
    // _Atomic-wrapped subobject directly, in-place.
    return This ? EvaluateInPlace(Result, Info, *This, &VIE)
                : Evaluate(Result, Info, &VIE);
  }

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      return ExprEvaluatorBaseTy::VisitCastExpr(E);
    case CK_NonAtomicToAtomic:
      return This ? EvaluateInPlace(Result, Info, *This, E->getSubExpr())
                  : Evaluate(Result, Info, E->getSubExpr());
    }
  }
};
} // end anonymous namespace

static bool EvaluateAtomic(const Expr *E, const LValue *This, APValue &Result,
                           EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isAtomicType());
  return AtomicExprEvaluator(Info, This, Result).Visit(E);
}

//===----------------------------------------------------------------------===//
// Void expression evaluation, primarily for a cast to void on the LHS of a
// comma operator
//===----------------------------------------------------------------------===//

namespace {
class VoidExprEvaluator
  : public ExprEvaluatorBase<VoidExprEvaluator> {
public:
  VoidExprEvaluator(EvalInfo &Info) : ExprEvaluatorBaseTy(Info) {}

  bool Success(const APValue &V, const Expr *e) { return true; }

  bool ZeroInitialization(const Expr *E) { return true; }

  bool VisitCastExpr(const CastExpr *E) {
    switch (E->getCastKind()) {
    default:
      return ExprEvaluatorBaseTy::VisitCastExpr(E);
    case CK_ToVoid:
      VisitIgnoredValue(E->getSubExpr());
      return true;
    }
  }

  bool VisitCallExpr(const CallExpr *E) {
    switch (E->getBuiltinCallee()) {
    case Builtin::BI__assume:
    case Builtin::BI__builtin_assume:
      // The argument is not evaluated!
      return true;

    case Builtin::BI__builtin_operator_delete:
      return HandleOperatorDeleteCall(Info, E);

    default:
      break;
    }

    return ExprEvaluatorBaseTy::VisitCallExpr(E);
  }

  bool VisitCXXDeleteExpr(const CXXDeleteExpr *E);
};
} // end anonymous namespace

bool VoidExprEvaluator::VisitCXXDeleteExpr(const CXXDeleteExpr *E) {
  // We cannot speculatively evaluate a delete expression.
  if (Info.SpeculativeEvaluationDepth)
    return false;

  FunctionDecl *OperatorDelete = E->getOperatorDelete();
  if (!OperatorDelete->isReplaceableGlobalAllocationFunction()) {
    Info.FFDiag(E, diag::note_constexpr_new_non_replaceable)
        << isa<CXXMethodDecl>(OperatorDelete) << OperatorDelete;
    return false;
  }

  const Expr *Arg = E->getArgument();

  LValue Pointer;
  if (!EvaluatePointer(Arg, Pointer, Info))
    return false;
  if (Pointer.Designator.Invalid)
    return false;

  // Deleting a null pointer has no effect.
  if (Pointer.isNullPointer()) {
    // This is the only case where we need to produce an extension warning:
    // the only other way we can succeed is if we find a dynamic allocation,
    // and we will have warned when we allocated it in that case.
    if (!Info.getLangOpts().CPlusPlus2a)
      Info.CCEDiag(E, diag::note_constexpr_new);
    return true;
  }

  Optional<DynAlloc *> Alloc = CheckDeleteKind(
      Info, E, Pointer, E->isArrayForm() ? DynAlloc::ArrayNew : DynAlloc::New);
  if (!Alloc)
    return false;
  QualType AllocType = Pointer.Base.getDynamicAllocType();

  // For the non-array case, the designator must be empty if the static type
  // does not have a virtual destructor.
  if (!E->isArrayForm() && Pointer.Designator.Entries.size() != 0 &&
      !hasVirtualDestructor(Arg->getType()->getPointeeType())) {
    Info.FFDiag(E, diag::note_constexpr_delete_base_nonvirt_dtor)
        << Arg->getType()->getPointeeType() << AllocType;
    return false;
  }

  // For a class type with a virtual destructor, the selected operator delete
  // is the one looked up when building the destructor.
  if (!E->isArrayForm() && !E->isGlobalDelete()) {
    const FunctionDecl *VirtualDelete = getVirtualOperatorDelete(AllocType);
    if (VirtualDelete &&
        !VirtualDelete->isReplaceableGlobalAllocationFunction()) {
      Info.FFDiag(E, diag::note_constexpr_new_non_replaceable)
          << isa<CXXMethodDecl>(VirtualDelete) << VirtualDelete;
      return false;
    }
  }

  if (!HandleDestruction(Info, E->getExprLoc(), Pointer.getLValueBase(),
                         (*Alloc)->Value, AllocType))
    return false;

  if (!Info.HeapAllocs.erase(Pointer.Base.dyn_cast<DynamicAllocLValue>())) {
    // The element was already erased. This means the destructor call also
    // deleted the object.
    // FIXME: This probably results in undefined behavior before we get this
    // far, and should be diagnosed elsewhere first.
    Info.FFDiag(E, diag::note_constexpr_double_delete);
    return false;
  }

  return true;
}

static bool EvaluateVoid(const Expr *E, EvalInfo &Info) {
  assert(E->isRValue() && E->getType()->isVoidType());
  return VoidExprEvaluator(Info).Visit(E);
}

//===----------------------------------------------------------------------===//
// Top level Expr::EvaluateAsRValue method.
//===----------------------------------------------------------------------===//

static bool Evaluate(APValue &Result, EvalInfo &Info, const Expr *E) {
  // In C, function designators are not lvalues, but we evaluate them as if they
  // are.
  QualType T = E->getType();
  if (E->isGLValue() || T->isFunctionType()) {
    LValue LV;
    if (!EvaluateLValue(E, LV, Info))
      return false;
    LV.moveInto(Result);
  } else if (T->isVectorType()) {
    if (!EvaluateVector(E, Result, Info))
      return false;
  } else if (T->isIntegralOrEnumerationType()) {
    if (!IntExprEvaluator(Info, Result).Visit(E))
      return false;
  } else if (T->hasPointerRepresentation()) {
    LValue LV;
    if (!EvaluatePointer(E, LV, Info))
      return false;
    LV.moveInto(Result);
  } else if (T->isRealFloatingType()) {
    llvm::APFloat F(0.0);
    if (!EvaluateFloat(E, F, Info))
      return false;
    Result = APValue(F);
  } else if (T->isAnyComplexType()) {
    ComplexValue C;
    if (!EvaluateComplex(E, C, Info))
      return false;
    C.moveInto(Result);
  } else if (T->isFixedPointType()) {
    if (!FixedPointExprEvaluator(Info, Result).Visit(E)) return false;
  } else if (T->isMemberPointerType()) {
    MemberPtr P;
    if (!EvaluateMemberPointer(E, P, Info))
      return false;
    P.moveInto(Result);
    return true;
  } else if (T->isArrayType()) {
    LValue LV;
    APValue &Value =
        Info.CurrentCall->createTemporary(E, T, false, LV);
    if (!EvaluateArray(E, LV, Value, Info))
      return false;
    Result = Value;
  } else if (T->isRecordType()) {
    LValue LV;
    APValue &Value = Info.CurrentCall->createTemporary(E, T, false, LV);
    if (!EvaluateRecord(E, LV, Value, Info))
      return false;
    Result = Value;
  } else if (T->isVoidType()) {
    if (!Info.getLangOpts().CPlusPlus11)
      Info.CCEDiag(E, diag::note_constexpr_nonliteral)
        << E->getType();
    if (!EvaluateVoid(E, Info))
      return false;
  } else if (T->isAtomicType()) {
    QualType Unqual = T.getAtomicUnqualifiedType();
    if (Unqual->isArrayType() || Unqual->isRecordType()) {
      LValue LV;
      APValue &Value = Info.CurrentCall->createTemporary(E, Unqual, false, LV);
      if (!EvaluateAtomic(E, &LV, Value, Info))
        return false;
    } else {
      if (!EvaluateAtomic(E, nullptr, Result, Info))
        return false;
    }
  } else if (Info.getLangOpts().CPlusPlus11) {
    Info.FFDiag(E, diag::note_constexpr_nonliteral) << E->getType();
    return false;
  } else {
    Info.FFDiag(E, diag::note_invalid_subexpr_in_const_expr);
    return false;
  }

  return true;
}

/// EvaluateInPlace - Evaluate an expression in-place in an APValue. In some
/// cases, the in-place evaluation is essential, since later initializers for
/// an object can indirectly refer to subobjects which were initialized earlier.
static bool EvaluateInPlace(APValue &Result, EvalInfo &Info, const LValue &This,
                            const Expr *E, bool AllowNonLiteralTypes) {
  assert(!E->isValueDependent());

  if (!AllowNonLiteralTypes && !CheckLiteralType(Info, E, &This))
    return false;

  if (E->isRValue()) {
    // Evaluate arrays and record types in-place, so that later initializers can
    // refer to earlier-initialized members of the object.
    QualType T = E->getType();
    if (T->isArrayType())
      return EvaluateArray(E, This, Result, Info);
    else if (T->isRecordType())
      return EvaluateRecord(E, This, Result, Info);
    else if (T->isAtomicType()) {
      QualType Unqual = T.getAtomicUnqualifiedType();
      if (Unqual->isArrayType() || Unqual->isRecordType())
        return EvaluateAtomic(E, &This, Result, Info);
    }
  }

  // For any other type, in-place evaluation is unimportant.
  return Evaluate(Result, Info, E);
}

/// EvaluateAsRValue - Try to evaluate this expression, performing an implicit
/// lvalue-to-rvalue cast if it is an lvalue.
static bool EvaluateAsRValue(EvalInfo &Info, const Expr *E, APValue &Result) {
  if (Info.EnableNewConstInterp) {
    if (!Info.Ctx.getInterpContext().evaluateAsRValue(Info, E, Result))
      return false;
  } else {
    if (E->getType().isNull())
      return false;

    if (!CheckLiteralType(Info, E))
      return false;

    if (!::Evaluate(Result, Info, E))
      return false;

    if (E->isGLValue()) {
      LValue LV;
      LV.setFrom(Info.Ctx, Result);
      if (!handleLValueToRValueConversion(Info, E, E->getType(), LV, Result))
        return false;
    }
  }

  // Check this core constant expression is a constant expression.
  return CheckConstantExpression(Info, E->getExprLoc(), E->getType(), Result) &&
         CheckMemoryLeaks(Info);
}

static bool FastEvaluateAsRValue(const Expr *Exp, Expr::EvalResult &Result,
                                 const ASTContext &Ctx, bool &IsConst) {
  // Fast-path evaluations of integer literals, since we sometimes see files
  // containing vast quantities of these.
  if (const IntegerLiteral *L = dyn_cast<IntegerLiteral>(Exp)) {
    Result.Val = APValue(APSInt(L->getValue(),
                                L->getType()->isUnsignedIntegerType()));
    IsConst = true;
    return true;
  }

  // This case should be rare, but we need to check it before we check on
  // the type below.
  if (Exp->getType().isNull()) {
    IsConst = false;
    return true;
  }

  // FIXME: Evaluating values of large array and record types can cause
  // performance problems. Only do so in C++11 for now.
  if (Exp->isRValue() && (Exp->getType()->isArrayType() ||
                          Exp->getType()->isRecordType()) &&
      !Ctx.getLangOpts().CPlusPlus11) {
    IsConst = false;
    return true;
  }
  return false;
}

static bool hasUnacceptableSideEffect(Expr::EvalStatus &Result,
                                      Expr::SideEffectsKind SEK) {
  return (SEK < Expr::SE_AllowSideEffects && Result.HasSideEffects) ||
         (SEK < Expr::SE_AllowUndefinedBehavior && Result.HasUndefinedBehavior);
}

static bool EvaluateAsRValue(const Expr *E, Expr::EvalResult &Result,
                             const ASTContext &Ctx, EvalInfo &Info) {
  bool IsConst;
  if (FastEvaluateAsRValue(E, Result, Ctx, IsConst))
    return IsConst;

  return EvaluateAsRValue(Info, E, Result.Val);
}

static bool EvaluateAsInt(const Expr *E, Expr::EvalResult &ExprResult,
                          const ASTContext &Ctx,
                          Expr::SideEffectsKind AllowSideEffects,
                          EvalInfo &Info) {
  if (!E->getType()->isIntegralOrEnumerationType())
    return false;

  if (!::EvaluateAsRValue(E, ExprResult, Ctx, Info) ||
      !ExprResult.Val.isInt() ||
      hasUnacceptableSideEffect(ExprResult, AllowSideEffects))
    return false;

  return true;
}

static bool EvaluateAsFixedPoint(const Expr *E, Expr::EvalResult &ExprResult,
                                 const ASTContext &Ctx,
                                 Expr::SideEffectsKind AllowSideEffects,
                                 EvalInfo &Info) {
  if (!E->getType()->isFixedPointType())
    return false;

  if (!::EvaluateAsRValue(E, ExprResult, Ctx, Info))
    return false;

  if (!ExprResult.Val.isFixedPoint() ||
      hasUnacceptableSideEffect(ExprResult, AllowSideEffects))
    return false;

  return true;
}

/// EvaluateAsRValue - Return true if this is a constant which we can fold using
/// any crazy technique (that has nothing to do with language standards) that
/// we want to.  If this function returns true, it returns the folded constant
/// in Result. If this expression is a glvalue, an lvalue-to-rvalue conversion
/// will be applied to the result.
bool Expr::EvaluateAsRValue(EvalResult &Result, const ASTContext &Ctx,
                            bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");
  EvalInfo Info(Ctx, Result, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = InConstantContext;
  return ::EvaluateAsRValue(this, Result, Ctx, Info);
}

bool Expr::EvaluateAsBooleanCondition(bool &Result, const ASTContext &Ctx,
                                      bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");
  EvalResult Scratch;
  return EvaluateAsRValue(Scratch, Ctx, InConstantContext) &&
         HandleConversionToBool(Scratch.Val, Result);
}

bool Expr::EvaluateAsInt(EvalResult &Result, const ASTContext &Ctx,
                         SideEffectsKind AllowSideEffects,
                         bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");
  EvalInfo Info(Ctx, Result, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = InConstantContext;
  return ::EvaluateAsInt(this, Result, Ctx, AllowSideEffects, Info);
}

bool Expr::EvaluateAsFixedPoint(EvalResult &Result, const ASTContext &Ctx,
                                SideEffectsKind AllowSideEffects,
                                bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");
  EvalInfo Info(Ctx, Result, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = InConstantContext;
  return ::EvaluateAsFixedPoint(this, Result, Ctx, AllowSideEffects, Info);
}

bool Expr::EvaluateAsFloat(APFloat &Result, const ASTContext &Ctx,
                           SideEffectsKind AllowSideEffects,
                           bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  if (!getType()->isRealFloatingType())
    return false;

  EvalResult ExprResult;
  if (!EvaluateAsRValue(ExprResult, Ctx, InConstantContext) ||
      !ExprResult.Val.isFloat() ||
      hasUnacceptableSideEffect(ExprResult, AllowSideEffects))
    return false;

  Result = ExprResult.Val.getFloat();
  return true;
}

bool Expr::EvaluateAsLValue(EvalResult &Result, const ASTContext &Ctx,
                            bool InConstantContext) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  EvalInfo Info(Ctx, Result, EvalInfo::EM_ConstantFold);
  Info.InConstantContext = InConstantContext;
  LValue LV;
  CheckedTemporaries CheckedTemps;
  if (!EvaluateLValue(this, LV, Info) || !Info.discardCleanups() ||
      Result.HasSideEffects ||
      !CheckLValueConstantExpression(Info, getExprLoc(),
                                     Ctx.getLValueReferenceType(getType()), LV,
                                     Expr::EvaluateForCodeGen, CheckedTemps))
    return false;

  LV.moveInto(Result.Val);
  return true;
}

bool Expr::EvaluateAsConstantExpr(EvalResult &Result, ConstExprUsage Usage,
                                  const ASTContext &Ctx) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  EvalInfo::EvaluationMode EM = EvalInfo::EM_ConstantExpression;
  EvalInfo Info(Ctx, Result, EM);
  Info.InConstantContext = true;

  if (!::Evaluate(Result.Val, Info, this) || Result.HasSideEffects)
    return false;

  if (!Info.discardCleanups())
    llvm_unreachable("Unhandled cleanup; missing full expression marker?");

  return CheckConstantExpression(Info, getExprLoc(), getStorageType(Ctx, this),
                                 Result.Val, Usage) &&
         CheckMemoryLeaks(Info);
}

bool Expr::EvaluateAsInitializer(APValue &Value, const ASTContext &Ctx,
                                 const VarDecl *VD,
                            SmallVectorImpl<PartialDiagnosticAt> &Notes) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  // FIXME: Evaluating initializers for large array and record types can cause
  // performance problems. Only do so in C++11 for now.
  if (isRValue() && (getType()->isArrayType() || getType()->isRecordType()) &&
      !Ctx.getLangOpts().CPlusPlus11)
    return false;

  Expr::EvalStatus EStatus;
  EStatus.Diag = &Notes;

  EvalInfo Info(Ctx, EStatus, VD->isConstexpr()
                                      ? EvalInfo::EM_ConstantExpression
                                      : EvalInfo::EM_ConstantFold);
  Info.setEvaluatingDecl(VD, Value);
  Info.InConstantContext = true;

  SourceLocation DeclLoc = VD->getLocation();
  QualType DeclTy = VD->getType();

  if (Info.EnableNewConstInterp) {
    auto &InterpCtx = const_cast<ASTContext &>(Ctx).getInterpContext();
    if (!InterpCtx.evaluateAsInitializer(Info, VD, Value))
      return false;
  } else {
    LValue LVal;
    LVal.set(VD);

    // C++11 [basic.start.init]p2:
    //  Variables with static storage duration or thread storage duration shall
    //  be zero-initialized before any other initialization takes place.
    // This behavior is not present in C.
    if (Ctx.getLangOpts().CPlusPlus && !VD->hasLocalStorage() &&
        !DeclTy->isReferenceType()) {
      ImplicitValueInitExpr VIE(DeclTy);
      if (!EvaluateInPlace(Value, Info, LVal, &VIE,
                           /*AllowNonLiteralTypes=*/true))
        return false;
    }

    if (!EvaluateInPlace(Value, Info, LVal, this,
                         /*AllowNonLiteralTypes=*/true) ||
        EStatus.HasSideEffects)
      return false;

    // At this point, any lifetime-extended temporaries are completely
    // initialized.
    Info.performLifetimeExtension();

    if (!Info.discardCleanups())
      llvm_unreachable("Unhandled cleanup; missing full expression marker?");
  }
  return CheckConstantExpression(Info, DeclLoc, DeclTy, Value) &&
         CheckMemoryLeaks(Info);
}

bool VarDecl::evaluateDestruction(
    SmallVectorImpl<PartialDiagnosticAt> &Notes) const {
  assert(getEvaluatedValue() && !getEvaluatedValue()->isAbsent() &&
         "cannot evaluate destruction of non-constant-initialized variable");

  Expr::EvalStatus EStatus;
  EStatus.Diag = &Notes;

  // Make a copy of the value for the destructor to mutate.
  APValue DestroyedValue = *getEvaluatedValue();

  EvalInfo Info(getASTContext(), EStatus, EvalInfo::EM_ConstantExpression);
  Info.setEvaluatingDecl(this, DestroyedValue,
                         EvalInfo::EvaluatingDeclKind::Dtor);
  Info.InConstantContext = true;

  SourceLocation DeclLoc = getLocation();
  QualType DeclTy = getType();

  LValue LVal;
  LVal.set(this);

  // FIXME: Consider storing whether this variable has constant destruction in
  // the EvaluatedStmt so that CodeGen can query it.
  if (!HandleDestruction(Info, DeclLoc, LVal.Base, DestroyedValue, DeclTy) ||
      EStatus.HasSideEffects)
    return false;

  if (!Info.discardCleanups())
    llvm_unreachable("Unhandled cleanup; missing full expression marker?");

  ensureEvaluatedStmt()->HasConstantDestruction = true;
  return true;
}

/// isEvaluatable - Call EvaluateAsRValue to see if this expression can be
/// constant folded, but discard the result.
bool Expr::isEvaluatable(const ASTContext &Ctx, SideEffectsKind SEK) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  EvalResult Result;
  return EvaluateAsRValue(Result, Ctx, /* in constant context */ true) &&
         !hasUnacceptableSideEffect(Result, SEK);
}

APSInt Expr::EvaluateKnownConstInt(const ASTContext &Ctx,
                    SmallVectorImpl<PartialDiagnosticAt> *Diag) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  EvalResult EVResult;
  EVResult.Diag = Diag;
  EvalInfo Info(Ctx, EVResult, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = true;

  bool Result = ::EvaluateAsRValue(this, EVResult, Ctx, Info);
  (void)Result;
  assert(Result && "Could not evaluate expression");
  assert(EVResult.Val.isInt() && "Expression did not evaluate to integer");

  return EVResult.Val.getInt();
}

APSInt Expr::EvaluateKnownConstIntCheckOverflow(
    const ASTContext &Ctx, SmallVectorImpl<PartialDiagnosticAt> *Diag) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  EvalResult EVResult;
  EVResult.Diag = Diag;
  EvalInfo Info(Ctx, EVResult, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = true;
  Info.CheckingForUndefinedBehavior = true;

  bool Result = ::EvaluateAsRValue(Info, this, EVResult.Val);
  (void)Result;
  assert(Result && "Could not evaluate expression");
  assert(EVResult.Val.isInt() && "Expression did not evaluate to integer");

  return EVResult.Val.getInt();
}

void Expr::EvaluateForOverflow(const ASTContext &Ctx) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  bool IsConst;
  EvalResult EVResult;
  if (!FastEvaluateAsRValue(this, EVResult, Ctx, IsConst)) {
    EvalInfo Info(Ctx, EVResult, EvalInfo::EM_IgnoreSideEffects);
    Info.CheckingForUndefinedBehavior = true;
    (void)::EvaluateAsRValue(Info, this, EVResult.Val);
  }
}

bool Expr::EvalResult::isGlobalLValue() const {
  assert(Val.isLValue());
  return IsGlobalLValue(Val.getLValueBase());
}


/// isIntegerConstantExpr - this recursive routine will test if an expression is
/// an integer constant expression.

/// FIXME: Pass up a reason why! Invalid operation in i-c-e, division by zero,
/// comma, etc

// CheckICE - This function does the fundamental ICE checking: the returned
// ICEDiag contains an ICEKind indicating whether the expression is an ICE,
// and a (possibly null) SourceLocation indicating the location of the problem.
//
// Note that to reduce code duplication, this helper does no evaluation
// itself; the caller checks whether the expression is evaluatable, and
// in the rare cases where CheckICE actually cares about the evaluated
// value, it calls into Evaluate.

namespace {

enum ICEKind {
  /// This expression is an ICE.
  IK_ICE,
  /// This expression is not an ICE, but if it isn't evaluated, it's
  /// a legal subexpression for an ICE. This return value is used to handle
  /// the comma operator in C99 mode, and non-constant subexpressions.
  IK_ICEIfUnevaluated,
  /// This expression is not an ICE, and is not a legal subexpression for one.
  IK_NotICE
};

struct ICEDiag {
  ICEKind Kind;
  SourceLocation Loc;

  ICEDiag(ICEKind IK, SourceLocation l) : Kind(IK), Loc(l) {}
};

}

static ICEDiag NoDiag() { return ICEDiag(IK_ICE, SourceLocation()); }

static ICEDiag Worst(ICEDiag A, ICEDiag B) { return A.Kind >= B.Kind ? A : B; }

static ICEDiag CheckEvalInICE(const Expr* E, const ASTContext &Ctx) {
  Expr::EvalResult EVResult;
  Expr::EvalStatus Status;
  EvalInfo Info(Ctx, Status, EvalInfo::EM_ConstantExpression);

  Info.InConstantContext = true;
  if (!::EvaluateAsRValue(E, EVResult, Ctx, Info) || EVResult.HasSideEffects ||
      !EVResult.Val.isInt())
    return ICEDiag(IK_NotICE, E->getBeginLoc());

  return NoDiag();
}

static ICEDiag CheckICE(const Expr* E, const ASTContext &Ctx) {
  assert(!E->isValueDependent() && "Should not see value dependent exprs!");
  if (!E->getType()->isIntegralOrEnumerationType())
    return ICEDiag(IK_NotICE, E->getBeginLoc());

  switch (E->getStmtClass()) {
#define ABSTRACT_STMT(Node)
#define STMT(Node, Base) case Expr::Node##Class:
#define EXPR(Node, Base)
#include "clang/AST/StmtNodes.inc"
  case Expr::PredefinedExprClass:
  case Expr::FloatingLiteralClass:
  case Expr::ImaginaryLiteralClass:
  case Expr::StringLiteralClass:
  case Expr::ArraySubscriptExprClass:
  case Expr::OMPArraySectionExprClass:
  case Expr::MemberExprClass:
  case Expr::CompoundAssignOperatorClass:
  case Expr::CompoundLiteralExprClass:
  case Expr::ExtVectorElementExprClass:
  case Expr::DesignatedInitExprClass:
  case Expr::ArrayInitLoopExprClass:
  case Expr::ArrayInitIndexExprClass:
  case Expr::NoInitExprClass:
  case Expr::DesignatedInitUpdateExprClass:
  case Expr::ImplicitValueInitExprClass:
  case Expr::ParenListExprClass:
  case Expr::VAArgExprClass:
  case Expr::AddrLabelExprClass:
  case Expr::StmtExprClass:
  case Expr::CXXMemberCallExprClass:
  case Expr::CUDAKernelCallExprClass:
  case Expr::CXXDynamicCastExprClass:
  case Expr::CXXTypeidExprClass:
  case Expr::CXXUuidofExprClass:
  case Expr::MSPropertyRefExprClass:
  case Expr::MSPropertySubscriptExprClass:
  case Expr::CXXNullPtrLiteralExprClass:
  case Expr::UserDefinedLiteralClass:
  case Expr::CXXThisExprClass:
  case Expr::CXXThrowExprClass:
  case Expr::CXXNewExprClass:
  case Expr::CXXDeleteExprClass:
  case Expr::CXXPseudoDestructorExprClass:
  case Expr::UnresolvedLookupExprClass:
  case Expr::TypoExprClass:
  case Expr::DependentScopeDeclRefExprClass:
  case Expr::CXXConstructExprClass:
  case Expr::CXXInheritedCtorInitExprClass:
  case Expr::CXXStdInitializerListExprClass:
  case Expr::CXXBindTemporaryExprClass:
  case Expr::ExprWithCleanupsClass:
  case Expr::CXXTemporaryObjectExprClass:
  case Expr::CXXUnresolvedConstructExprClass:
  case Expr::CXXDependentScopeMemberExprClass:
  case Expr::UnresolvedMemberExprClass:
  case Expr::ObjCStringLiteralClass:
  case Expr::ObjCBoxedExprClass:
  case Expr::ObjCArrayLiteralClass:
  case Expr::ObjCDictionaryLiteralClass:
  case Expr::ObjCEncodeExprClass:
  case Expr::ObjCMessageExprClass:
  case Expr::ObjCSelectorExprClass:
  case Expr::ObjCProtocolExprClass:
  case Expr::ObjCIvarRefExprClass:
  case Expr::ObjCPropertyRefExprClass:
  case Expr::ObjCSubscriptRefExprClass:
  case Expr::ObjCIsaExprClass:
  case Expr::ObjCAvailabilityCheckExprClass:
  case Expr::ShuffleVectorExprClass:
  case Expr::ConvertVectorExprClass:
  case Expr::BlockExprClass:
  case Expr::NoStmtClass:
  case Expr::OpaqueValueExprClass:
  case Expr::PackExpansionExprClass:
  case Expr::SubstNonTypeTemplateParmPackExprClass:
  case Expr::FunctionParmPackExprClass:
  case Expr::AsTypeExprClass:
  case Expr::ObjCIndirectCopyRestoreExprClass:
  case Expr::MaterializeTemporaryExprClass:
  case Expr::PseudoObjectExprClass:
  case Expr::AtomicExprClass:
  case Expr::LambdaExprClass:
  case Expr::CXXFoldExprClass:
  case Expr::CoawaitExprClass:
  case Expr::DependentCoawaitExprClass:
  case Expr::CoyieldExprClass:
    return ICEDiag(IK_NotICE, E->getBeginLoc());

  case Expr::InitListExprClass: {
    // C++03 [dcl.init]p13: If T is a scalar type, then a declaration of the
    // form "T x = { a };" is equivalent to "T x = a;".
    // Unless we're initializing a reference, T is a scalar as it is known to be
    // of integral or enumeration type.
    if (E->isRValue())
      if (cast<InitListExpr>(E)->getNumInits() == 1)
        return CheckICE(cast<InitListExpr>(E)->getInit(0), Ctx);
    return ICEDiag(IK_NotICE, E->getBeginLoc());
  }

  case Expr::SizeOfPackExprClass:
  case Expr::GNUNullExprClass:
  case Expr::SourceLocExprClass:
    return NoDiag();

  case Expr::SubstNonTypeTemplateParmExprClass:
    return
      CheckICE(cast<SubstNonTypeTemplateParmExpr>(E)->getReplacement(), Ctx);

  case Expr::ConstantExprClass:
    return CheckICE(cast<ConstantExpr>(E)->getSubExpr(), Ctx);

  case Expr::ParenExprClass:
    return CheckICE(cast<ParenExpr>(E)->getSubExpr(), Ctx);
  case Expr::GenericSelectionExprClass:
    return CheckICE(cast<GenericSelectionExpr>(E)->getResultExpr(), Ctx);
  case Expr::IntegerLiteralClass:
  case Expr::FixedPointLiteralClass:
  case Expr::CharacterLiteralClass:
  case Expr::ObjCBoolLiteralExprClass:
  case Expr::CXXBoolLiteralExprClass:
  case Expr::CXXScalarValueInitExprClass:
  case Expr::TypeTraitExprClass:
  case Expr::ConceptSpecializationExprClass:
  case Expr::RequiresExprClass:
  case Expr::ArrayTypeTraitExprClass:
  case Expr::ExpressionTraitExprClass:
  case Expr::CXXNoexceptExprClass:
    return NoDiag();
  case Expr::CallExprClass:
  case Expr::CXXOperatorCallExprClass: {
    // C99 6.6/3 allows function calls within unevaluated subexpressions of
    // constant expressions, but they can never be ICEs because an ICE cannot
    // contain an operand of (pointer to) function type.
    const CallExpr *CE = cast<CallExpr>(E);
    if (CE->getBuiltinCallee())
      return CheckEvalInICE(E, Ctx);
    return ICEDiag(IK_NotICE, E->getBeginLoc());
  }
  case Expr::CXXRewrittenBinaryOperatorClass:
    return CheckICE(cast<CXXRewrittenBinaryOperator>(E)->getSemanticForm(),
                    Ctx);
  case Expr::DeclRefExprClass: {
    if (isa<EnumConstantDecl>(cast<DeclRefExpr>(E)->getDecl()))
      return NoDiag();
    const ValueDecl *D = cast<DeclRefExpr>(E)->getDecl();
    if (Ctx.getLangOpts().CPlusPlus &&
        D && IsConstNonVolatile(D->getType())) {
      // Parameter variables are never constants.  Without this check,
      // getAnyInitializer() can find a default argument, which leads
      // to chaos.
      if (isa<ParmVarDecl>(D))
        return ICEDiag(IK_NotICE, cast<DeclRefExpr>(E)->getLocation());

      // C++ 7.1.5.1p2
      //   A variable of non-volatile const-qualified integral or enumeration
      //   type initialized by an ICE can be used in ICEs.
      if (const VarDecl *Dcl = dyn_cast<VarDecl>(D)) {
        if (!Dcl->getType()->isIntegralOrEnumerationType())
          return ICEDiag(IK_NotICE, cast<DeclRefExpr>(E)->getLocation());

        const VarDecl *VD;
        // Look for a declaration of this variable that has an initializer, and
        // check whether it is an ICE.
        if (Dcl->getAnyInitializer(VD) && VD->checkInitIsICE())
          return NoDiag();
        else
          return ICEDiag(IK_NotICE, cast<DeclRefExpr>(E)->getLocation());
      }
    }
    return ICEDiag(IK_NotICE, E->getBeginLoc());
  }
  case Expr::UnaryOperatorClass: {
    const UnaryOperator *Exp = cast<UnaryOperator>(E);
    switch (Exp->getOpcode()) {
    case UO_PostInc:
    case UO_PostDec:
    case UO_PreInc:
    case UO_PreDec:
    case UO_AddrOf:
    case UO_Deref:
    case UO_Coawait:
      // C99 6.6/3 allows increment and decrement within unevaluated
      // subexpressions of constant expressions, but they can never be ICEs
      // because an ICE cannot contain an lvalue operand.
      return ICEDiag(IK_NotICE, E->getBeginLoc());
    case UO_Extension:
    case UO_LNot:
    case UO_Plus:
    case UO_Minus:
    case UO_Not:
    case UO_Real:
    case UO_Imag:
      return CheckICE(Exp->getSubExpr(), Ctx);
    }
    llvm_unreachable("invalid unary operator class");
  }
  case Expr::OffsetOfExprClass: {
    // Note that per C99, offsetof must be an ICE. And AFAIK, using
    // EvaluateAsRValue matches the proposed gcc behavior for cases like
    // "offsetof(struct s{int x[4];}, x[1.0])".  This doesn't affect
    // compliance: we should warn earlier for offsetof expressions with
    // array subscripts that aren't ICEs, and if the array subscripts
    // are ICEs, the value of the offsetof must be an integer constant.
    return CheckEvalInICE(E, Ctx);
  }
  case Expr::UnaryExprOrTypeTraitExprClass: {
    const UnaryExprOrTypeTraitExpr *Exp = cast<UnaryExprOrTypeTraitExpr>(E);
    if ((Exp->getKind() ==  UETT_SizeOf) &&
        Exp->getTypeOfArgument()->isVariableArrayType())
      return ICEDiag(IK_NotICE, E->getBeginLoc());
    return NoDiag();
  }
  case Expr::BinaryOperatorClass: {
    const BinaryOperator *Exp = cast<BinaryOperator>(E);
    switch (Exp->getOpcode()) {
    case BO_PtrMemD:
    case BO_PtrMemI:
    case BO_Assign:
    case BO_MulAssign:
    case BO_DivAssign:
    case BO_RemAssign:
    case BO_AddAssign:
    case BO_SubAssign:
    case BO_ShlAssign:
    case BO_ShrAssign:
    case BO_AndAssign:
    case BO_XorAssign:
    case BO_OrAssign:
      // C99 6.6/3 allows assignments within unevaluated subexpressions of
      // constant expressions, but they can never be ICEs because an ICE cannot
      // contain an lvalue operand.
      return ICEDiag(IK_NotICE, E->getBeginLoc());

    case BO_Mul:
    case BO_Div:
    case BO_Rem:
    case BO_Add:
    case BO_Sub:
    case BO_Shl:
    case BO_Shr:
    case BO_LT:
    case BO_GT:
    case BO_LE:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
    case BO_And:
    case BO_Xor:
    case BO_Or:
    case BO_Comma:
    case BO_Cmp: {
      ICEDiag LHSResult = CheckICE(Exp->getLHS(), Ctx);
      ICEDiag RHSResult = CheckICE(Exp->getRHS(), Ctx);
      if (Exp->getOpcode() == BO_Div ||
          Exp->getOpcode() == BO_Rem) {
        // EvaluateAsRValue gives an error for undefined Div/Rem, so make sure
        // we don't evaluate one.
        if (LHSResult.Kind == IK_ICE && RHSResult.Kind == IK_ICE) {
          llvm::APSInt REval = Exp->getRHS()->EvaluateKnownConstInt(Ctx);
          if (REval == 0)
            return ICEDiag(IK_ICEIfUnevaluated, E->getBeginLoc());
          if (REval.isSigned() && REval.isAllOnesValue()) {
            llvm::APSInt LEval = Exp->getLHS()->EvaluateKnownConstInt(Ctx);
            if (LEval.isMinSignedValue())
              return ICEDiag(IK_ICEIfUnevaluated, E->getBeginLoc());
          }
        }
      }
      if (Exp->getOpcode() == BO_Comma) {
        if (Ctx.getLangOpts().C99) {
          // C99 6.6p3 introduces a strange edge case: comma can be in an ICE
          // if it isn't evaluated.
          if (LHSResult.Kind == IK_ICE && RHSResult.Kind == IK_ICE)
            return ICEDiag(IK_ICEIfUnevaluated, E->getBeginLoc());
        } else {
          // In both C89 and C++, commas in ICEs are illegal.
          return ICEDiag(IK_NotICE, E->getBeginLoc());
        }
      }
      return Worst(LHSResult, RHSResult);
    }
    case BO_LAnd:
    case BO_LOr: {
      ICEDiag LHSResult = CheckICE(Exp->getLHS(), Ctx);
      ICEDiag RHSResult = CheckICE(Exp->getRHS(), Ctx);
      if (LHSResult.Kind == IK_ICE && RHSResult.Kind == IK_ICEIfUnevaluated) {
        // Rare case where the RHS has a comma "side-effect"; we need
        // to actually check the condition to see whether the side
        // with the comma is evaluated.
        if ((Exp->getOpcode() == BO_LAnd) !=
            (Exp->getLHS()->EvaluateKnownConstInt(Ctx) == 0))
          return RHSResult;
        return NoDiag();
      }

      return Worst(LHSResult, RHSResult);
    }
    }
    llvm_unreachable("invalid binary operator kind");
  }
  case Expr::ImplicitCastExprClass:
  case Expr::CStyleCastExprClass:
  case Expr::CXXFunctionalCastExprClass:
  case Expr::CXXStaticCastExprClass:
  case Expr::CXXReinterpretCastExprClass:
  case Expr::CXXConstCastExprClass:
  case Expr::ObjCBridgedCastExprClass: {
    const Expr *SubExpr = cast<CastExpr>(E)->getSubExpr();
    if (isa<ExplicitCastExpr>(E)) {
      if (const FloatingLiteral *FL
            = dyn_cast<FloatingLiteral>(SubExpr->IgnoreParenImpCasts())) {
        unsigned DestWidth = Ctx.getIntWidth(E->getType());
        bool DestSigned = E->getType()->isSignedIntegerOrEnumerationType();
        APSInt IgnoredVal(DestWidth, !DestSigned);
        bool Ignored;
        // If the value does not fit in the destination type, the behavior is
        // undefined, so we are not required to treat it as a constant
        // expression.
        if (FL->getValue().convertToInteger(IgnoredVal,
                                            llvm::APFloat::rmTowardZero,
                                            &Ignored) & APFloat::opInvalidOp)
          return ICEDiag(IK_NotICE, E->getBeginLoc());
        return NoDiag();
      }
    }
    switch (cast<CastExpr>(E)->getCastKind()) {
    case CK_LValueToRValue:
    case CK_AtomicToNonAtomic:
    case CK_NonAtomicToAtomic:
    case CK_NoOp:
    case CK_IntegralToBoolean:
    case CK_IntegralCast:
      return CheckICE(SubExpr, Ctx);
    default:
      return ICEDiag(IK_NotICE, E->getBeginLoc());
    }
  }
  case Expr::BinaryConditionalOperatorClass: {
    const BinaryConditionalOperator *Exp = cast<BinaryConditionalOperator>(E);
    ICEDiag CommonResult = CheckICE(Exp->getCommon(), Ctx);
    if (CommonResult.Kind == IK_NotICE) return CommonResult;
    ICEDiag FalseResult = CheckICE(Exp->getFalseExpr(), Ctx);
    if (FalseResult.Kind == IK_NotICE) return FalseResult;
    if (CommonResult.Kind == IK_ICEIfUnevaluated) return CommonResult;
    if (FalseResult.Kind == IK_ICEIfUnevaluated &&
        Exp->getCommon()->EvaluateKnownConstInt(Ctx) != 0) return NoDiag();
    return FalseResult;
  }
  case Expr::ConditionalOperatorClass: {
    const ConditionalOperator *Exp = cast<ConditionalOperator>(E);
    // If the condition (ignoring parens) is a __builtin_constant_p call,
    // then only the true side is actually considered in an integer constant
    // expression, and it is fully evaluated.  This is an important GNU
    // extension.  See GCC PR38377 for discussion.
    if (const CallExpr *CallCE
        = dyn_cast<CallExpr>(Exp->getCond()->IgnoreParenCasts()))
      if (CallCE->getBuiltinCallee() == Builtin::BI__builtin_constant_p)
        return CheckEvalInICE(E, Ctx);
    ICEDiag CondResult = CheckICE(Exp->getCond(), Ctx);
    if (CondResult.Kind == IK_NotICE)
      return CondResult;

    ICEDiag TrueResult = CheckICE(Exp->getTrueExpr(), Ctx);
    ICEDiag FalseResult = CheckICE(Exp->getFalseExpr(), Ctx);

    if (TrueResult.Kind == IK_NotICE)
      return TrueResult;
    if (FalseResult.Kind == IK_NotICE)
      return FalseResult;
    if (CondResult.Kind == IK_ICEIfUnevaluated)
      return CondResult;
    if (TrueResult.Kind == IK_ICE && FalseResult.Kind == IK_ICE)
      return NoDiag();
    // Rare case where the diagnostics depend on which side is evaluated
    // Note that if we get here, CondResult is 0, and at least one of
    // TrueResult and FalseResult is non-zero.
    if (Exp->getCond()->EvaluateKnownConstInt(Ctx) == 0)
      return FalseResult;
    return TrueResult;
  }
  case Expr::CXXDefaultArgExprClass:
    return CheckICE(cast<CXXDefaultArgExpr>(E)->getExpr(), Ctx);
  case Expr::CXXDefaultInitExprClass:
    return CheckICE(cast<CXXDefaultInitExpr>(E)->getExpr(), Ctx);
  case Expr::ChooseExprClass: {
    return CheckICE(cast<ChooseExpr>(E)->getChosenSubExpr(), Ctx);
  }
  case Expr::BuiltinBitCastExprClass: {
    if (!checkBitCastConstexprEligibility(nullptr, Ctx, cast<CastExpr>(E)))
      return ICEDiag(IK_NotICE, E->getBeginLoc());
    return CheckICE(cast<CastExpr>(E)->getSubExpr(), Ctx);
  }
  }

  llvm_unreachable("Invalid StmtClass!");
}

/// Evaluate an expression as a C++11 integral constant expression.
static bool EvaluateCPlusPlus11IntegralConstantExpr(const ASTContext &Ctx,
                                                    const Expr *E,
                                                    llvm::APSInt *Value,
                                                    SourceLocation *Loc) {
  if (!E->getType()->isIntegralOrUnscopedEnumerationType()) {
    if (Loc) *Loc = E->getExprLoc();
    return false;
  }

  APValue Result;
  if (!E->isCXX11ConstantExpr(Ctx, &Result, Loc))
    return false;

  if (!Result.isInt()) {
    if (Loc) *Loc = E->getExprLoc();
    return false;
  }

  if (Value) *Value = Result.getInt();
  return true;
}

bool Expr::isIntegerConstantExpr(const ASTContext &Ctx,
                                 SourceLocation *Loc) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  if (Ctx.getLangOpts().CPlusPlus11)
    return EvaluateCPlusPlus11IntegralConstantExpr(Ctx, this, nullptr, Loc);

  ICEDiag D = CheckICE(this, Ctx);
  if (D.Kind != IK_ICE) {
    if (Loc) *Loc = D.Loc;
    return false;
  }
  return true;
}

bool Expr::isIntegerConstantExpr(llvm::APSInt &Value, const ASTContext &Ctx,
                                 SourceLocation *Loc, bool isEvaluated) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  if (Ctx.getLangOpts().CPlusPlus11)
    return EvaluateCPlusPlus11IntegralConstantExpr(Ctx, this, &Value, Loc);

  if (!isIntegerConstantExpr(Ctx, Loc))
    return false;

  // The only possible side-effects here are due to UB discovered in the
  // evaluation (for instance, INT_MAX + 1). In such a case, we are still
  // required to treat the expression as an ICE, so we produce the folded
  // value.
  EvalResult ExprResult;
  Expr::EvalStatus Status;
  EvalInfo Info(Ctx, Status, EvalInfo::EM_IgnoreSideEffects);
  Info.InConstantContext = true;

  if (!::EvaluateAsInt(this, ExprResult, Ctx, SE_AllowSideEffects, Info))
    llvm_unreachable("ICE cannot be evaluated!");

  Value = ExprResult.Val.getInt();
  return true;
}

bool Expr::isCXX98IntegralConstantExpr(const ASTContext &Ctx) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  return CheckICE(this, Ctx).Kind == IK_ICE;
}

bool Expr::isCXX11ConstantExpr(const ASTContext &Ctx, APValue *Result,
                               SourceLocation *Loc) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  // We support this checking in C++98 mode in order to diagnose compatibility
  // issues.
  assert(Ctx.getLangOpts().CPlusPlus);

  // Build evaluation settings.
  Expr::EvalStatus Status;
  SmallVector<PartialDiagnosticAt, 8> Diags;
  Status.Diag = &Diags;
  EvalInfo Info(Ctx, Status, EvalInfo::EM_ConstantExpression);

  APValue Scratch;
  bool IsConstExpr =
      ::EvaluateAsRValue(Info, this, Result ? *Result : Scratch) &&
      // FIXME: We don't produce a diagnostic for this, but the callers that
      // call us on arbitrary full-expressions should generally not care.
      Info.discardCleanups() && !Status.HasSideEffects;

  if (!Diags.empty()) {
    IsConstExpr = false;
    if (Loc) *Loc = Diags[0].first;
  } else if (!IsConstExpr) {
    // FIXME: This shouldn't happen.
    if (Loc) *Loc = getExprLoc();
  }

  return IsConstExpr;
}

bool Expr::EvaluateWithSubstitution(APValue &Value, ASTContext &Ctx,
                                    const FunctionDecl *Callee,
                                    ArrayRef<const Expr*> Args,
                                    const Expr *This) const {
  assert(!isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  Expr::EvalStatus Status;
  EvalInfo Info(Ctx, Status, EvalInfo::EM_ConstantExpressionUnevaluated);
  Info.InConstantContext = true;

  LValue ThisVal;
  const LValue *ThisPtr = nullptr;
  if (This) {
#ifndef NDEBUG
    auto *MD = dyn_cast<CXXMethodDecl>(Callee);
    assert(MD && "Don't provide `this` for non-methods.");
    assert(!MD->isStatic() && "Don't provide `this` for static methods.");
#endif
    if (!This->isValueDependent() &&
        EvaluateObjectArgument(Info, This, ThisVal) &&
        !Info.EvalStatus.HasSideEffects)
      ThisPtr = &ThisVal;

    // Ignore any side-effects from a failed evaluation. This is safe because
    // they can't interfere with any other argument evaluation.
    Info.EvalStatus.HasSideEffects = false;
  }

  ArgVector ArgValues(Args.size());
  for (ArrayRef<const Expr*>::iterator I = Args.begin(), E = Args.end();
       I != E; ++I) {
    if ((*I)->isValueDependent() ||
        !Evaluate(ArgValues[I - Args.begin()], Info, *I) ||
        Info.EvalStatus.HasSideEffects)
      // If evaluation fails, throw away the argument entirely.
      ArgValues[I - Args.begin()] = APValue();

    // Ignore any side-effects from a failed evaluation. This is safe because
    // they can't interfere with any other argument evaluation.
    Info.EvalStatus.HasSideEffects = false;
  }

  // Parameter cleanups happen in the caller and are not part of this
  // evaluation.
  Info.discardCleanups();
  Info.EvalStatus.HasSideEffects = false;

  // Build fake call to Callee.
  CallStackFrame Frame(Info, Callee->getLocation(), Callee, ThisPtr,
                       ArgValues.data());
  // FIXME: Missing ExprWithCleanups in enable_if conditions?
  FullExpressionRAII Scope(Info);
  return Evaluate(Value, Info, this) && Scope.destroy() &&
         !Info.EvalStatus.HasSideEffects;
}

bool Expr::isPotentialConstantExpr(const FunctionDecl *FD,
                                   SmallVectorImpl<
                                     PartialDiagnosticAt> &Diags) {
  // FIXME: It would be useful to check constexpr function templates, but at the
  // moment the constant expression evaluator cannot cope with the non-rigorous
  // ASTs which we build for dependent expressions.
  if (FD->isDependentContext())
    return true;

  Expr::EvalStatus Status;
  Status.Diag = &Diags;

  EvalInfo Info(FD->getASTContext(), Status, EvalInfo::EM_ConstantExpression);
  Info.InConstantContext = true;
  Info.CheckingPotentialConstantExpression = true;

  // The constexpr VM attempts to compile all methods to bytecode here.
  if (Info.EnableNewConstInterp) {
    Info.Ctx.getInterpContext().isPotentialConstantExpr(Info, FD);
    return Diags.empty();
  }

  const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(FD);
  const CXXRecordDecl *RD = MD ? MD->getParent()->getCanonicalDecl() : nullptr;

  // Fabricate an arbitrary expression on the stack and pretend that it
  // is a temporary being used as the 'this' pointer.
  LValue This;
  ImplicitValueInitExpr VIE(RD ? Info.Ctx.getRecordType(RD) : Info.Ctx.IntTy);
  This.set({&VIE, Info.CurrentCall->Index});

  ArrayRef<const Expr*> Args;

  APValue Scratch;
  if (const CXXConstructorDecl *CD = dyn_cast<CXXConstructorDecl>(FD)) {
    // Evaluate the call as a constant initializer, to allow the construction
    // of objects of non-literal types.
    Info.setEvaluatingDecl(This.getLValueBase(), Scratch);
    HandleConstructorCall(&VIE, This, Args, CD, Info, Scratch);
  } else {
    SourceLocation Loc = FD->getLocation();
    HandleFunctionCall(Loc, FD, (MD && MD->isInstance()) ? &This : nullptr,
                       Args, FD->getBody(), Info, Scratch, nullptr);
  }

  return Diags.empty();
}

bool Expr::isPotentialConstantExprUnevaluated(Expr *E,
                                              const FunctionDecl *FD,
                                              SmallVectorImpl<
                                                PartialDiagnosticAt> &Diags) {
  assert(!E->isValueDependent() &&
         "Expression evaluator can't be called on a dependent expression.");

  Expr::EvalStatus Status;
  Status.Diag = &Diags;

  EvalInfo Info(FD->getASTContext(), Status,
                EvalInfo::EM_ConstantExpressionUnevaluated);
  Info.InConstantContext = true;
  Info.CheckingPotentialConstantExpression = true;

  // Fabricate a call stack frame to give the arguments a plausible cover story.
  ArrayRef<const Expr*> Args;
  ArgVector ArgValues(0);
  bool Success = EvaluateArgs(Args, ArgValues, Info, FD);
  (void)Success;
  assert(Success &&
         "Failed to set up arguments for potential constant evaluation");
  CallStackFrame Frame(Info, SourceLocation(), FD, nullptr, ArgValues.data());

  APValue ResultScratch;
  Evaluate(ResultScratch, Info, E);
  return Diags.empty();
}

bool Expr::tryEvaluateObjectSize(uint64_t &Result, ASTContext &Ctx,
                                 unsigned Type) const {
  if (!getType()->isPointerType())
    return false;

  Expr::EvalStatus Status;
  EvalInfo Info(Ctx, Status, EvalInfo::EM_ConstantFold);
  return tryEvaluateBuiltinObjectSize(this, Type, Info, Result);
}
