/*-
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Stratix10 Reset Manager.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/sysctl.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>

struct rstmgr_softc {
	struct resource		*res[1];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	device_t		dev;
};

static struct resource_spec rstmgr_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

#define	READ4(_sc, _reg)	bus_read_4((_sc)->res[0], _reg)
#define	WRITE4(_sc, _reg, _val)	bus_write_4((_sc)->res[0], _reg, _val)

#define	RSTMGR_BRGMODRST	0x2C	/* Bridge Module Reset */
#define	BRGMODRST_FPGA2HPS	(1 << 2)
#define	BRGMODRST_LWHPS2FPGA	(1 << 1)
#define	BRGMODRST_HPS2FPGA	(1 << 0)

enum {
	RSTMGR_SYSCTL_FPGA2HPS,
	RSTMGR_SYSCTL_LWHPS2FPGA,
	RSTMGR_SYSCTL_HPS2FPGA
};

static int
rstmgr_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct rstmgr_softc *sc;
	int enable;
	int err;
	int reg;
	int bit;

	sc = arg1;

	switch (arg2) {
	case RSTMGR_SYSCTL_FPGA2HPS:
		bit = BRGMODRST_FPGA2HPS;
		break;
	case RSTMGR_SYSCTL_LWHPS2FPGA:
		bit = BRGMODRST_LWHPS2FPGA;
		break;
	case RSTMGR_SYSCTL_HPS2FPGA:
		bit = BRGMODRST_HPS2FPGA;
		break;
	default:
		return (1);
	}

	reg = READ4(sc, RSTMGR_BRGMODRST);
	enable = reg & bit ? 0 : 1;

	err = sysctl_handle_int(oidp, &enable, 0, req);
	if (err || !req->newptr)
		return (err);

	if (enable == 1)
		reg &= ~(bit);
	else if (enable == 0)
		reg |= (bit);
	else
		return (EINVAL);

	WRITE4(sc, RSTMGR_BRGMODRST, reg);

	return (0);
}

static int
rstmgr_add_sysctl(struct rstmgr_softc *sc)
{
	struct sysctl_oid_list *children;
	struct sysctl_ctx_list *ctx;

	ctx = device_get_sysctl_ctx(sc->dev);
	children = SYSCTL_CHILDREN(device_get_sysctl_tree(sc->dev));

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "fpga2hps",
	    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    sc, RSTMGR_SYSCTL_FPGA2HPS,
	    rstmgr_sysctl, "I", "Enable fpga2hps bridge");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "lwhps2fpga",
	    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    sc, RSTMGR_SYSCTL_LWHPS2FPGA,
	    rstmgr_sysctl, "I", "Enable lwhps2fpga bridge");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "hps2fpga",
	    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    sc, RSTMGR_SYSCTL_HPS2FPGA,
	    rstmgr_sysctl, "I", "Enable hps2fpga bridge");

	return (0);
}

static int
rstmgr_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "altr,rst-mgr"))
		return (ENXIO);

	device_set_desc(dev, "Reset Manager");

	return (BUS_PROBE_DEFAULT);
}

static int
rstmgr_attach(device_t dev)
{
	struct rstmgr_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, rstmgr_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	rstmgr_add_sysctl(sc);

	return (0);
}

static device_method_t rstmgr_methods[] = {
	DEVMETHOD(device_probe,		rstmgr_probe),
	DEVMETHOD(device_attach,	rstmgr_attach),
	{ 0, 0 }
};

static driver_t rstmgr_driver = {
	"rstmgr",
	rstmgr_methods,
	sizeof(struct rstmgr_softc),
};

DRIVER_MODULE(rstmgr, simplebus, rstmgr_driver, 0, 0);
