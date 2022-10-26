# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app import habbing
from keri.app.cli.common import existing

import json
from json import JSONDecodeError
import sys
from keri.core import eventing, parsing, coring, scheming,routing
from keri.help import helping
from keri.vdr import viring, verifying
from keri.vdr.eventing import Tevery

parser = argparse.ArgumentParser(description='Verify ACDC credential')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--text', '-t', help='Text or file (starts with "@") to load ACDC credential', required=True)


def handler(args):
    """
    Verify ACDC credential

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(verify, **kwa)]


def verify(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]

    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    try:
        with existing.existingHab(name=name, alias=alias, base=base, bran=bran) as (hby, hab):

            txt = args.text
            if txt.startswith("@"):
                f = open(txt[1:], "r")
                data = f.read()
            else:
                data = txt

            # sigers = hab.sign(ser=data.encode("utf-8"),
            #                   verfers=hab.kever.verfers,
            #                   indexed=True)

            # for idx, siger in enumerate(sigers):
            #     print("{}. {}".format(idx+1, siger.qb64))

            
            reger = viring.Reger(name=hab.name, db=hab.db, temp=False)
            verfer = verifying.Verifier(hby=hby, reger=reger)

            rvy = routing.Revery(db=hby.db)
            kvy = eventing.Kevery(db=hby.db,
                          lax=True,
                          local=False,
                          rvy=rvy)
            # kvy.registerReplyRoutes(router=rvy.rtr)

            tvy = Tevery(reger=verfer.reger,
                 db=hby.db,
                 local=False)            

            parser = parsing.Parser(kvy=kvy,
                                    tvy=tvy,
                                    rvy=rvy,
                                    vry=verfer)

            parser.parse(ims=bytearray(data.encode("utf-8")))

            # kevery = eventing.Kevery(db=hab.db)
            # psr = parsing.Parser(kvy=kevery)
            # psr.parse(ims=bytearray(data.encode("utf-8")))


    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
    except FileNotFoundError:
        print("unable to open file", args.text[1:])
