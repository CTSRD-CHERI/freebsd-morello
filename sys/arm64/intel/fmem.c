/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_subr.h>

#include <machine/bus.h>

#define	FMEM_MAXDEVS		128

struct fmem_dev {
	struct cdev		*cdev;
	uint64_t		offset;
	uint64_t		length;
};

struct fmem_softc {
	struct resource		*res[1];
	device_t		dev;
	int			mem_size;
	int			mem_start;
	struct fmem_dev		fmem[FMEM_MAXDEVS];
	int			ndevs;
};

static struct resource_spec fmem_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

struct fmem_request {
	uint32_t offset;
	uint32_t data;
	uint32_t access_width;
};

#define	FMEM_READ	_IOWR('X', 1, struct fmem_request)
#define FMEM_WRITE	_IOWR('X', 2, struct fmem_request)

static int
fmemopen(struct cdev *dev __unused, int flags, int fmt __unused,
    struct thread *td)
{

	return (0);
}

static int
fmemioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	struct fmem_request *req;
	struct fmem_softc *sc;
	uint64_t addr;
	int unit;

	sc = dev->si_drv1;
	unit = dev2unit(dev);

	req = (struct fmem_request *)data;
	if ((req->offset + req->access_width) > sc->fmem[unit].length)
		return (ERANGE);

	addr = sc->fmem[unit].offset + req->offset;
	if (addr & (req->access_width - 1))
		return (ENXIO);

	switch (cmd) {
	case FMEM_READ:
		switch (req->access_width) {
		case 1:
			req->data = bus_read_1(sc->res[0], addr);
			break;
		case 2:
			req->data = bus_read_2(sc->res[0], addr);
			break;
		case 4:
			req->data = bus_read_4(sc->res[0], addr);
			break;
		}
		break;
	case FMEM_WRITE:
		switch (req->access_width) {
		case 1:
			bus_write_1(sc->res[0], addr, req->data);
			break;
		case 2:
			bus_write_2(sc->res[0], addr, req->data);
			break;
		case 4:
			bus_write_4(sc->res[0], addr, req->data);
			break;
		}
	}

	return (0);
}

static struct cdevsw fmem_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	0,
	.d_open =	fmemopen,
	.d_read =	NULL,
	.d_write =	NULL,
	.d_ioctl =	fmemioctl,
	.d_mmap =	NULL,
	.d_name =	"fmem",
};

static int
fmem_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "cheri,fmem"))
		return (ENXIO);

	device_set_desc(dev, "CHERI FPGA memory");
	return (BUS_PROBE_DEFAULT);
}

static int
fmem_attach(device_t dev)
{
	struct fmem_softc *sc;
	phandle_t node, child;
	bus_addr_t paddr;
	bus_size_t psize;
	char *name;
	int error;
	int u;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, fmem_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory info */
	sc->mem_size = rman_get_size(sc->res[0]);
	sc->mem_start = rman_get_start(sc->res[0]);
	sc->ndevs = 0;

	node = ofw_bus_get_node(dev);

	/* Optional group. */
	child = ofw_bus_find_child(node, "regions");
	if (child)
		node = child;

	for (child = OF_child(node), u = 0; child != 0 && u < FMEM_MAXDEVS;
	    child = OF_peer(child), u ++) {

		error = OF_getprop_alloc(child, "name", (void **)&name);
		if (error == -1)
			continue;

		error = ofw_reg_to_paddr(child, 0, &paddr, &psize, NULL);
		if (error) {
			device_printf(sc->dev,
			    "ofw_reg_to_paddr() failed, error %d\n", error);
			continue;
		}

		device_printf(sc->dev, "region name %s paddr %lx size %lx\n",
		    name, paddr, psize);

		if ((psize & 0xfff) != 0) {
			device_printf(sc->dev,
			    "psize must be multiple of PAGE_SIZE\n");
			continue;
		}

		sc->fmem[u].cdev = make_dev(&fmem_cdevsw, u, UID_ROOT,
		    GID_KMEM, 0640, "fmem_%s", name);
		if (sc->fmem[u].cdev == NULL) {
			device_printf(sc->dev, "can't create device\n");
			continue;
		}

		sc->fmem[u].cdev->si_drv1 = sc;
		sc->fmem[u].offset = paddr;
		sc->fmem[u].length = psize;
		sc->ndevs++;
	}

	return (0);
}

static int
fmem_detach(device_t dev)
{
	struct fmem_softc *sc;
	int i;

	sc = device_get_softc(dev);

	for (i = 0; i < sc->ndevs; i++)
		destroy_dev(sc->fmem[i].cdev);

	bus_release_resources(dev, fmem_spec, sc->res);

	return (0);
}

static device_method_t fmem_methods[] = {
	DEVMETHOD(device_probe,		fmem_probe),
	DEVMETHOD(device_attach,	fmem_attach),
	DEVMETHOD(device_detach,	fmem_detach),
	{ 0, 0 }
};

static driver_t fmem_driver = {
	"fmem",
	fmem_methods,
	sizeof(struct fmem_softc),
};

DRIVER_MODULE(fmem, simplebus, fmem_driver, 0, 0);
