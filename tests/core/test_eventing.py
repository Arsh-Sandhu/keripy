# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import pytest

import pysodium
import blake3
from math import ceil

from keri.kering import Version
from keri.kering import ValidationError, EmptyMaterialError, DerivationError

from keri.core.coring import CrySelDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import CryOneSizes, CryOneRawSizes, CryTwoSizes, CryTwoRawSizes
from keri.core.coring import CryFourSizes, CryFourRawSizes, CrySizes, CryRawSizes
from keri.core.coring import CryMat, Verfer, Signer, Diger, Nexter, Aider
from keri.core.coring import generateSigners
from keri.core.coring import SigSelDex, SigTwoDex, SigTwoSizes, SigTwoRawSizes
from keri.core.coring import SigFourDex, SigFourSizes, SigFourRawSizes
from keri.core.coring import SigFiveDex, SigFiveSizes, SigFiveRawSizes
from keri.core.coring import SigSizes, SigRawSizes
from keri.core.coring import IntToB64, B64ToInt
from keri.core.coring import SigMat
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever
from keri.core.coring import Serder
from keri.core.coring import Ilkage, Ilks

from keri.core.eventing import TraitDex, incept, rotate, interact, Kever, Kevery


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt')

    assert isinstance(Ilks, Ilkage)

    assert Ilks.icp == 'icp'
    assert Ilks.rot == 'rot'
    assert Ilks.ixn == 'ixn'
    assert Ilks.dip == 'dip'
    assert Ilks.drt == 'drt'

    assert 'icp' in Ilks
    assert 'rot' in Ilks
    assert 'ixn' in Ilks
    assert 'dip' in Ilks
    assert 'drt' in Ilks

def test_keyeventfuncs():
    """
    Test the support functionality for key event generation functions

    """
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')

    # Inception: Non-transferable (ephemeral) case
    signer0 = Signer(raw=seed, transferable=False)  #  original signing keypair non transferable
    assert signer0.code == CryOneDex.Ed25519_Seed
    assert signer0.verfer.code == CryOneDex.Ed25519N
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["aid"] == 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["nxt"] == ""
    assert serder.raw == (b'{"vs":"KERI10JSON0000cf_","aid":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c","sn":"0","ilk":"icp","sith":"1","keys":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                          b'Z-Wk1x4ejhcc"],"nxt":"","toad":"0","wits":[],"cnfg":[]}')


    with pytest.raises(DerivationError):
        serder = incept(keys=keys0, nxt="ABCDE")  # non-empty nxt wtih non-transferable code

    # Inception: Transferable Case but abandoned in incept so equivalent
    signer0 = Signer(raw=seed)  #  original signing keypair transferable default
    assert signer0.code == CryOneDex.Ed25519_Seed
    assert signer0.verfer.code == CryOneDex.Ed25519
    keys0 = [signer0.verfer.qb64]
    serder = incept(keys=keys0)  #  default nxt is empty so abandoned
    assert serder.ked["aid"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder.ked["nxt"] == ""
    assert serder.raw == (b'{"vs":"KERI10JSON0000cf_","aid":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                          b'c","sn":"0","ilk":"icp","sith":"1","keys":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                          b'Z-Wk1x4ejhcc"],"nxt":"","toad":"0","wits":[],"cnfg":[]}')


    # Inception: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
            b'\x98Y\xdd\xe8')
    signer1 = Signer(raw=seed1)  #  next signing keypair transferable is default
    assert signer1.code == CryOneDex.Ed25519_Seed
    assert signer1.verfer.code == CryOneDex.Ed25519
    keys1 = [signer1.verfer.qb64]
    # compute nxt digest
    nexter1 = Nexter(keys=keys1)  # dfault sith is 1
    assert nexter1.sith == '1'  # default from keys
    nxt1 = nexter1.qb64  # transferable so nxt is not empty
    assert nxt1 == 'ERoAnIgbnFekiKsGwQFaPub2lnB6GU4I80702IKn4aPs'
    serder0 = incept(keys=keys0, nxt=nxt1)
    aid = serder0.ked["aid"]
    assert serder0.ked["aid"] == 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    assert serder0.ked["sn"] == '0'
    assert serder0.ked["nxt"] == nxt1
    assert serder0.raw == (b'{"vs":"KERI10JSON0000fb_","aid":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"0","ilk":"icp","sith":"1","keys":["DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_y'
                           b'Z-Wk1x4ejhcc"],"nxt":"ERoAnIgbnFekiKsGwQFaPub2lnB6GU4I80702IKn4aPs","toad":"'
                           b'0","wits":[],"cnfg":[]}')
    assert serder0.dig == 'Ec1jq8Lj3vwpmbfN4t6rrtSY7XpLdtz8oQwtVLt8Rj7M'


    # Rotation: Transferable not abandoned i.e. next not empty
    # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed2 = (b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2'
            b'e\xf9AL\x1aeK\xafj\xa1pB')
    signer2 = Signer(raw=seed2)  #  next signing keypair transferable is default
    assert signer2.code == CryOneDex.Ed25519_Seed
    assert signer2.verfer.code == CryOneDex.Ed25519
    keys2 = [signer2.verfer.qb64]
    # compute nxt digest
    nexter2 = Nexter(keys=keys2)
    assert nexter2.sith == '1'  # default from keys
    nxt2 = nexter2.qb64  # transferable so nxt is not empty
    assert nxt2 == 'ECeM2JsaL9-ljwnIlsEYoPUJCv8zWcIeWmPSl2G14OP0'
    serder1 = rotate(aid=aid, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
    assert serder1.ked["aid"] == aid
    assert serder1.ked["sn"] == '1'
    assert serder1.ked["nxt"] == nxt2
    assert serder1.ked["dig"] == serder0.dig
    assert serder1.raw == (b'{"vs":"KERI10JSON00013a_","aid":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"1","ilk":"rot","dig":"Ec1jq8Lj3vwpmbfN4t6rrtSY7XpLdtz8oQwtVLt8Rj7M"'
                           b',"sith":"1","keys":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"nxt":"E'
                           b'CeM2JsaL9-ljwnIlsEYoPUJCv8zWcIeWmPSl2G14OP0","toad":"0","cuts":[],"adds":[],'
                           b'"data":[]}')

    # Interaction:
    serder2 = interact(aid=aid, dig=serder1.dig, sn=2)
    assert serder2.ked["aid"] == aid
    assert serder2.ked["sn"] == '2'
    assert serder2.ked["dig"] == serder1.dig
    assert serder2.raw == (b'{"vs":"KERI10JSON0000a3_","aid":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                           b'c","sn":"2","ilk":"ixn","dig":"E6uPKdq0fuah7wctnRX26SjHCkM_tZ_vUQ59UtrSEeuY"'
                           b',"data":[]}')


    """ Done Test """



def test_kever():
    """
    Test the support functionality for Kever class
    Key Event Verifier
    """
    with pytest.raises(TypeError):
        kever = Kever()

    # Transferable case
    # Setup inception key event dict
    # create current key
    sith = 1  #  one signer
    skp0 = Signer()  #  original signing keypair transferable default
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    nxtsith = 1 #  one signer
    skp1 = Signer()  #  next signing keypair transferable is default
    assert skp1.code == CryOneDex.Ed25519_Seed
    assert skp1.verfer.code == CryOneDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute nxt digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so nxt is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                aid="",  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=keys,  # list of signing keys each qual Base64
                nxt=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )


    # Derive AID from ked
    aid0 = Aider(ked=ked0)
    assert aid0.code == CryOneDex.Ed25519

    # update ked with aid
    ked0["aid"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    kever = Kever(serder=tser0, sigers=[tsig0])


    """ Done Test """


def test_keyeventsequence_0():
    """
    Test generation of a sequence of key events

    """
    # manual process to generate a list of secrets
    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    # root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    #root = '0AZxWJGkCkpDcHuVG4GM1KVw'
    #rooter = CryMat(qb64=root)
    #assert rooter.qb64 == root
    #assert rooter.code == CryTwoDex.Seed_128
    #signers = generateSigners(root=rooter.raw, count=8, transferable=True)
    #secrets = [signer.qb64 for signer in signers]
    #secrets =generateSecrets(root=rooter.raw, count=8, transferable=True)

    # Test sequence of events given set of secrets
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create signers
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [signer.qb64 for signer in signers] == secrets

    pubkeys = [signer.verfer.qb64 for  signer in  signers]
    assert pubkeys == [
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI',
                        'DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8',
                        'DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ',
                        'D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU',
                        'D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM',
                        'DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4',
                        'DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg'
                     ]

    # Event 0  Inception Transferable (nxt digest not empty)
    keys0 = [signers[0].verfer.qb64]
    # compute nxt digest from keys1
    keys1 = [signers[1].verfer.qb64]
    nexter1 = Nexter(keys=keys1)
    assert nexter1.sith == '1'
    nxt1 = nexter1.qb64  # transferable so nxt is not empty
    assert nxt1 == 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    serder0 = incept(keys=keys0, nxt=nxt1)
    aid = serder0.ked["aid"]
    assert serder0.ked["aid"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    assert serder0.ked["sn"] == '0'
    assert serder0.ked["sith"] == '1'
    assert serder0.ked["keys"] == keys0
    assert serder0.ked["nxt"] == nxt1
    assert serder0.dig == 'EyH1dHvVcntw1w-sQoIwrSN7DA0hfS8yQhz0H7u-gsmc'

    # sign serialization and verify signature
    sig0 = signers[0].sign(serder0.raw, index=0)
    assert signers[0].verfer.verify(sig0.raw, serder0.raw)
    # create key event verifier state
    kever = Kever(serder=serder0, sigers=[sig0])
    assert kever.aider.qb64 == aid
    assert kever.sn == 0
    assert kever.diger.qb64 == serder0.dig
    assert kever.ilk == Ilks.icp
    assert kever.sith == 1
    assert [verfer.qb64 for verfer in kever.verfers] == keys0
    assert kever.nexter.qb64 == nxt1
    assert kever.estOnly == False
    assert kever.nonTrans == False

    # Event 1 Rotation Transferable
    # compute nxt digest from keys2
    keys2 = [signers[2].verfer.qb64]
    nexter2 = Nexter(keys=keys2)
    assert nexter2.sith == '1'
    nxt2 = nexter2.qb64  # transferable so nxt is not empty
    assert nxt2 == 'EoWDoTGQZ6lJ19LsaV4g42k5gccsB_-ttYHOft6kuYZk'
    serder1 = rotate(aid=aid, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
    assert serder1.ked["aid"] == aid
    assert serder1.ked["sn"] == '1'
    assert serder1.ked["sith"] == '1'
    assert serder1.ked["keys"] == keys1
    assert serder1.ked["nxt"] == nxt2
    assert serder1.ked["dig"] == serder0.dig

    # sign serialization and verify signature
    sig1 = signers[1].sign(serder1.raw, index=0)
    assert signers[1].verfer.verify(sig1.raw, serder1.raw)
    # update key event verifier state
    kever.update(serder=serder1, sigers=[sig1])
    assert kever.aider.qb64 == aid
    assert kever.sn == 1
    assert kever.diger.qb64 == serder1.dig
    assert kever.ilk == Ilks.rot
    assert [verfer.qb64 for verfer in kever.verfers] == keys1
    assert kever.nexter.qb64 == nxt2

    # Event 2 Rotation Transferable
    # compute nxt digest from keys3
    keys3 = [signers[3].verfer.qb64]
    nexter3 = Nexter(keys=keys3)
    nxt3 = nexter3.qb64  # transferable so nxt is not empty
    serder2 = rotate(aid=aid, keys=keys2, dig=serder1.dig, nxt=nxt3, sn=2)
    assert serder2.ked["aid"] == aid
    assert serder2.ked["sn"] == '2'
    assert serder2.ked["keys"] == keys2
    assert serder2.ked["nxt"] == nxt3
    assert serder2.ked["dig"] == serder1.dig

    # sign serialization and verify signature
    sig2 = signers[2].sign(serder2.raw, index=0)
    assert signers[2].verfer.verify(sig2.raw, serder2.raw)
    # update key event verifier state
    kever.update(serder=serder2, sigers=[sig2])
    assert kever.aider.qb64 == aid
    assert kever.sn == 2
    assert kever.diger.qb64 == serder2.dig
    assert kever.ilk == Ilks.rot
    assert [verfer.qb64 for verfer in kever.verfers] == keys2
    assert kever.nexter.qb64 == nxt3

    # Event 3 Interaction
    serder3 = interact(aid=aid, dig=serder2.dig, sn=3)
    assert serder3.ked["aid"] == aid
    assert serder3.ked["sn"] == '3'
    assert serder3.ked["dig"] == serder2.dig

    # sign serialization and verify signature
    sig3 = signers[2].sign(serder3.raw, index=0)
    assert signers[2].verfer.verify(sig3.raw, serder3.raw)
    # update key event verifier state
    kever.update(serder=serder3, sigers=[sig3])
    assert kever.aider.qb64 == aid
    assert kever.sn == 3
    assert kever.diger.qb64 == serder3.dig
    assert kever.ilk == Ilks.ixn
    assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
    assert kever.nexter.qb64 == nxt3  # no change

    # Event 4 Interaction
    serder4 = interact(aid=aid, dig=serder3.dig, sn=4)
    assert serder4.ked["aid"] == aid
    assert serder4.ked["sn"] == '4'
    assert serder4.ked["dig"] == serder3.dig

    # sign serialization and verify signature
    sig4 = signers[2].sign(serder4.raw, index=0)
    assert signers[2].verfer.verify(sig4.raw, serder4.raw)
    # update key event verifier state
    kever.update(serder=serder4, sigers=[sig4])
    assert kever.aider.qb64 == aid
    assert kever.sn == 4
    assert kever.diger.qb64 == serder4.dig
    assert kever.ilk == Ilks.ixn
    assert [verfer.qb64 for verfer in kever.verfers] == keys2  # no change
    assert kever.nexter.qb64 == nxt3  # no change

    # Event 5 Rotation Transferable
    # compute nxt digest from keys4
    keys4 = [signers[4].verfer.qb64]
    nexter4 = Nexter(keys=keys4)
    nxt4 = nexter4.qb64  # transferable so nxt is not empty
    serder5 = rotate(aid=aid, keys=keys3, dig=serder4.dig, nxt=nxt4, sn=5)
    assert serder5.ked["aid"] == aid
    assert serder5.ked["sn"] == '5'
    assert serder5.ked["keys"] == keys3
    assert serder5.ked["nxt"] == nxt4
    assert serder5.ked["dig"] == serder4.dig

    # sign serialization and verify signature
    sig5 = signers[3].sign(serder5.raw, index=0)
    assert signers[3].verfer.verify(sig5.raw, serder5.raw)
    # update key event verifier state
    kever.update(serder=serder5, sigers=[sig5])
    assert kever.aider.qb64 == aid
    assert kever.sn == 5
    assert kever.diger.qb64 == serder5.dig
    assert kever.ilk == Ilks.rot
    assert [verfer.qb64 for verfer in kever.verfers] == keys3
    assert kever.nexter.qb64 == nxt4

    # Event 6 Interaction
    serder6 = interact(aid=aid, dig=serder5.dig, sn=6)
    assert serder6.ked["aid"] == aid
    assert serder6.ked["sn"] == '6'
    assert serder6.ked["dig"] == serder5.dig

    # sign serialization and verify signature
    sig6 = signers[3].sign(serder6.raw, index=0)
    assert signers[3].verfer.verify(sig6.raw, serder6.raw)
    # update key event verifier state
    kever.update(serder=serder6, sigers=[sig6])
    assert kever.aider.qb64 == aid
    assert kever.sn == 6
    assert kever.diger.qb64 == serder6.dig
    assert kever.ilk == Ilks.ixn
    assert [verfer.qb64 for verfer in kever.verfers] == keys3  # no change
    assert kever.nexter.qb64 == nxt4    # no change

    # Event 7 Rotation to null NonTransferable Abandon
    nxt5 = ""  # nxt digest is empty
    serder7 = rotate(aid=aid, keys=keys4, dig=serder6.dig, nxt=nxt5, sn=7)
    assert serder7.ked["aid"] == aid
    assert serder7.ked["sn"] == '7'
    assert serder7.ked["keys"] == keys4
    assert serder7.ked["nxt"] == nxt5
    assert serder7.ked["dig"] == serder6.dig

    # sign serialization and verify signature
    sig7 = signers[4].sign(serder7.raw, index=0)
    assert signers[4].verfer.verify(sig7.raw, serder7.raw)
    # update key event verifier state
    kever.update(serder=serder7, sigers=[sig7])
    assert kever.aider.qb64 == aid
    assert kever.sn == 7
    assert kever.diger.qb64 == serder7.dig
    assert kever.ilk == Ilks.rot
    assert [verfer.qb64 for verfer in kever.verfers] == keys4
    assert kever.nexter == None
    assert kever.nonTrans

    # Event 8 Interaction
    serder8 = interact(aid=aid, dig=serder7.dig, sn=8)
    assert serder8.ked["aid"] == aid
    assert serder8.ked["sn"] == '8'
    assert serder8.ked["dig"] == serder7.dig

    # sign serialization and verify signature
    sig8 = signers[4].sign(serder8.raw, index=0)
    assert signers[4].verfer.verify(sig8.raw, serder8.raw)
    # update key event verifier state
    with pytest.raises(ValidationError):  # nontransferable so reject update
        kever.update(serder=serder8, sigers=[sig8])

    # Event 8 Rotation
    keys5 = [signers[5].verfer.qb64]
    nexter5 = Nexter(keys=keys5)
    nxt5 = nexter4.qb64  # transferable so nxt is not empty
    serder8 = rotate(aid=aid, keys=keys5, dig=serder7.dig, nxt=nxt5, sn=8)
    assert serder8.ked["aid"] == aid
    assert serder8.ked["sn"] == '8'
    assert serder8.ked["dig"] == serder7.dig

    # sign serialization and verify signature
    sig8 = signers[4].sign(serder8.raw, index=0)
    assert signers[4].verfer.verify(sig8.raw, serder8.raw)
    # update key event verifier state
    with pytest.raises(ValidationError):  # nontransferable so reject update
        kever.update(serder=serder8, sigers=[sig8])

    """ Done Test """

def test_keyeventsequence_1():
    """
    Test generation of a sequence of key events
    Establishment only
    """

    # Test sequence of events given set of secrets
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create signers
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [signer.qb64 for signer in signers] == secrets

    pubkeys = [signer.verfer.qb64 for  signer in  signers]
    assert pubkeys == [
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI',
                        'DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8',
                        'DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ',
                        'D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU',
                        'D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM',
                        'DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4',
                        'DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg'
                     ]

    # New Sequence establishment only

    # Event 0  Inception Transferable (nxt digest not empty)
    keys0 = [signers[0].verfer.qb64]
    # compute nxt digest from keys1
    keys1 = [signers[1].verfer.qb64]
    nexter1 = Nexter(keys=keys1)
    nxt1 = nexter1.qb64  # transferable so nxt is not empty
    cnfg = [dict(trait=TraitDex.EstOnly)]
    serder0 = incept(keys=keys0, nxt=nxt1, cnfg=cnfg)
    aid = serder0.ked["aid"]
    assert serder0.ked["aid"] == 'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'
    assert serder0.ked["sn"] == '0'
    assert serder0.ked["sith"] == '1'
    assert serder0.ked["keys"] == keys0
    assert serder0.ked["nxt"] == nxt1
    assert serder0.ked["cnfg"] == cnfg
    # sign serialization and verify signature
    sig0 = signers[0].sign(serder0.raw, index=0)
    assert signers[0].verfer.verify(sig0.raw, serder0.raw)
    # create key event verifier state
    kever = Kever(serder=serder0, sigers=[sig0])
    assert kever.aider.qb64 == aid
    assert kever.sn == 0
    assert kever.diger.qb64 == serder0.dig
    assert kever.ilk == Ilks.icp
    assert kever.sith == 1
    assert [verfer.qb64 for verfer in kever.verfers] == keys0
    assert kever.nexter.qb64 == nxt1
    assert kever.estOnly == True
    assert kever.nonTrans == False

    # Event 1 Interaction
    serder1 = interact(aid=aid, dig=serder0.dig, sn=1)
    assert serder1.ked["aid"] == aid
    assert serder1.ked["sn"] == '1'
    assert serder1.ked["dig"] == serder0.dig
    # sign serialization and verify signature
    sig1 = signers[0].sign(serder1.raw, index=0)
    assert signers[0].verfer.verify(sig1.raw, serder1.raw)
    # update key event verifier state
    with pytest.raises(ValidationError):  # attempt ixn with estOnly
        kever.update(serder=serder1, sigers=[sig1])


    # Event 1 Rotation Transferable
    # compute nxt digest from keys2
    keys2 = [signers[2].verfer.qb64]
    nexter2 = Nexter(keys=keys2)
    assert nexter2.sith == '1'
    nxt2 = nexter2.qb64  # transferable so nxt is not empty
    assert nxt2 == 'EoWDoTGQZ6lJ19LsaV4g42k5gccsB_-ttYHOft6kuYZk'
    serder1 = rotate(aid=aid, keys=keys1, dig=serder0.dig, nxt=nxt2, sn=1)
    assert serder1.ked["aid"] == aid
    assert serder1.ked["sn"] == '1'
    assert serder1.ked["sith"] == '1'
    assert serder1.ked["keys"] == keys1
    assert serder1.ked["nxt"] == nxt2
    assert serder1.ked["dig"] == serder0.dig

    # sign serialization and verify signature
    sig1 = signers[1].sign(serder1.raw, index=0)
    assert signers[1].verfer.verify(sig1.raw, serder1.raw)
    # update key event verifier state
    kever.update(serder=serder1, sigers=[sig1])
    assert kever.aider.qb64 == aid
    assert kever.sn == 1
    assert kever.diger.qb64 == serder1.dig
    assert kever.ilk == Ilks.rot
    assert [verfer.qb64 for verfer in kever.verfers] == keys1
    assert kever.nexter.qb64 == nxt2

    """ Done Test """

def test_kevery():
    """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """
    kevery = Kevery()
    """ Done Test """

def test_process_nontransferable():
    """
    Test process of generating and validating key event messages
    """

    # Ephemeral (Nontransferable) case
    skp0 = Signer(transferable=False)  #  original signing keypair non transferable
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519N

    # Derive AID by merely assigning verifier public key
    aid0 = Aider(qb64=skp0.verfer.qb64)
    assert aid0.code == CryOneDex.Ed25519N

    # Ephemeral may be used without inception event
    # but when used with inception event must be compatible event
    sn = 0  #  inception event so 0
    sith = 1 #  one signer
    nxt = ""  # non-transferable so nxt is empty
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                aid=aid0.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aid0.qb64],  # list of signing keys each qual Base64
                nxt=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )

    # verify derivation of aid0 from ked0
    assert aid0.verify(ked=ked0)

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create packet
    msgb0 = bytearray(tser0.raw + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw

    del msgb0[:rser0.size]  # strip off event from front

    # extract attached sigs if any
    if "idxs" not in rser0.ked or not rser0.ked["idxs"]:  # no info on attached sigs
        assert False

    else:
        ridxs = rser0.ked["idxs"]  # exract signature indexes
        if isinstance(ridxs, list):
            for idx in ridxs:
                pass
            assert False

        else:
            nrsigs = int(ridxs, 16)
            assert nrsigs == 1
            keys = rser0.ked["keys"]
            for i in range(nrsigs): # verify each attached signature
                rsig = SigMat(qb64=msgb0)
                assert rsig.index == 0
                verfer = Verfer(qb64=keys[rsig.index])
                assert verfer.qb64 == aid0.qb64
                assert verfer.qb64 == skp0.verfer.qb64
                assert verfer.verify(rsig.raw, rser0.raw)
                del msgb0[:len(rsig.qb64)]

    # verify aid
    raid0 = Aider(qb64=rser0.ked["aid"])
    assert raid0.verify(ked=rser0.ked)
    """ Done Test """

def test_process_transferable():
    """
    Test process of generating and validating key event messages
    """
    # Transferable case
    # Setup inception key event dict
    # create current key
    sith = 1  #  one signer
    skp0 = Signer()  #  original signing keypair transferable default
    assert skp0.code == CryOneDex.Ed25519_Seed
    assert skp0.verfer.code == CryOneDex.Ed25519
    keys = [skp0.verfer.qb64]

    # create next key
    nxtsith = 1 #  one signer
    skp1 = Signer()  #  next signing keypair transferable is default
    assert skp1.code == CryOneDex.Ed25519_Seed
    assert skp1.verfer.code == CryOneDex.Ed25519
    nxtkeys = [skp1.verfer.qb64]
    # compute nxt digest
    nexter = Nexter(sith=nxtsith, keys=nxtkeys)
    nxt = nexter.qb64  # transferable so next is not empty

    sn = 0  #  inception event so 0
    toad = 0  # no witnesses
    nsigs = 1  #  one attached signature unspecified index

    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                aid="",  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=keys,  # list of signing keys each qual Base64
                nxt=nxt,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
                idxs="{:x}".format(nsigs)  # single lowercase hex string
               )


    # Derive AID from ked
    aid0 = Aider(ked=ked0)
    assert aid0.code == CryOneDex.Ed25519

    # update ked with aid
    ked0["aid"] = aid0.qb64

    # Serialize ked0
    tser0 = Serder(ked=ked0)

    # sign serialization
    tsig0 = skp0.sign(tser0.raw, index=0)

    # verify signature
    assert skp0.verfer.verify(tsig0.raw, tser0.raw)

    # create packet
    msgb0 = bytearray(tser0.raw + tsig0.qb64b)

    # deserialize packet
    rser0 = Serder(raw=msgb0)
    assert rser0.raw == tser0.raw

    del msgb0[:rser0.size]  # strip off event from front

    # extract attached idxs if any
    if "idxs" not in rser0.ked or not rser0.ked["idxs"]:  # no info on attached idxs
        assert False

    else:
        ridxs = rser0.ked["idxs"]  # exract signature indexes
        if isinstance(ridxs, list):
            for idx in ridxs:
                pass
            assert False

        else:
            nrsigs = int(ridxs, 16)
            assert nrsigs == 1
            keys = rser0.ked["keys"]
            for i in range(nrsigs): # verify each attached signature
                rsig = SigMat(qb64=msgb0)
                assert rsig.index == 0
                verfer = Verfer(qb64=keys[rsig.index])
                assert verfer.qb64 == aid0.qb64
                assert verfer.qb64 == skp0.verfer.qb64
                assert verfer.verify(rsig.raw, rser0.raw)
                del msgb0[:len(rsig.qb64)]

    # verify aid
    raid0 = Aider(qb64=rser0.ked["aid"])
    assert raid0.verify(ked=rser0.ked)

    #verify nxt digest from event is still valid
    rnxt1 = Nexter(qb64=rser0.ked["nxt"])
    assert rnxt1.verify(sith=nxtsith, keys=nxtkeys)
    """ Done Test """



def test_process_manual():
    """
    Test manual process of generating and validating inception key event message
    """
    # create qualified aid in basic format
    # workflow is start with seed and save seed. Seed in this case is 32 bytes
    # aidseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    aidseed = b'p6\xac\xb7\x10R\xc4\x9c7\xe8\x97\xa3\xdb!Z\x08\xdf\xfaR\x07\x9a\xb3\x1e\x9d\xda\xee\xa2\xbc\xe4;w\xae'
    assert len(aidseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(aidseed)
    assert verkey == b'\xaf\x96\xb0p\xfb0\xa7\xd0\xa4\x18\xc9\xdc\x1d\x86\xc2:\x98\xf7?t\x1b\xde.\xcc\xcb;\x8a\xb0\xa2O\xe7K'
    assert len(verkey) == 32

    # create qualified aid in basic format
    aidmat = CryMat(raw=verkey, code=CryOneDex.Ed25519)
    assert aidmat.qb64 == 'Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'

    # create qualified next public key in basic format
    nxtseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    nxtseed = b'm\x04\xf9\xe4\xd5`<\x91]>y\xe9\xe5$\xb6\xd8\xd5D\xb7\xea\xf6\x13\xd4\x08TYL\xb6\xc7 D\xc7'
    assert len(nxtseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(nxtseed)
    assert verkey == b'\xf5DOB:<\xcd\x16\x18\x9b\x83L\xa5\x0c\x98X\x90C\x1a\xb30O\xa5\x0f\xe39l\xa6\xdfX\x185'
    assert len(verkey) == 32

    # create qualified nxt key in basic format
    nxtkeymat = CryMat(raw=verkey, code=CryOneDex.Ed25519)
    assert nxtkeymat.qb64 == 'D9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'

    # create nxt digest
    nxtsith =  "{:x}".format(1)  # lowecase hex no leading zeros
    assert nxtsith == "1"
    nxts = []  # create list to concatenate for hashing
    nxts.append(nxtsith.encode("utf-8"))
    nxts.append(nxtkeymat.qb64.encode("utf-8"))
    nxtsraw = b''.join(nxts)
    assert nxtsraw == b'1D9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'
    nxtdig = blake3.blake3(nxtsraw).digest()
    assert nxtdig == b'\xdeWy\xd3=\xcb`\xce\xe9\x99\x0cF\xdd\xb2C6\x03\xa7F\rS\xd6\xfem\x99\x89\xac`<\xaa\x88\xd2'

    nxtdigmat = CryMat(raw=nxtdig, code=CryOneDex.Blake3_256)
    assert nxtdigmat.qb64 == 'E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI'

    sn =  0
    sith = 1
    toad = 0
    index = 0

    #create key event dict
    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                aid=aidmat.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aidmat.qb64],  # list of signing keys each qual Base64
                nxt=nxtdigmat.qb64,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                cnfg=[],  # list of config ordered mappings may be empty
                idxs=["{:x}".format(index)]  # optional list of lowercase hex strings no leading zeros or single lowercase hex string
               )


    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"vs":"KERI10JSON000108_","aid":"Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'
                          b'","sn":"0","ilk":"icp","sith":"1","keys":["Dr5awcPswp9CkGMncHYbCOpj3P3Qb3i7M'
                          b'yzuKsKJP50s"],"nxt":"E3ld50z3LYM7pmQxG3bJDNgOnRg1T1v5tmYmsYDyqiNI","toad":"'
                          b'0","wits":[],"cnfg":[],"idxs":["0"]}')

    assert txsrdr.size == 264

    txdig = blake3.blake3(txsrdr.raw).digest()
    txdigmat = CryMat(raw=txdig, code=CryOneDex.Blake3_256)
    assert txdigmat.qb64 == 'ErN5rbHXT5Nqt6B4rnwQhXzzZS67trqLaADghoHYQlfM'

    assert txsrdr.dig == txdigmat.qb64

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  #  sigkey = seed + verkey
    assert len(sig0raw) == 64

    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result  # None if verifies successfully else raises ValueError

    txsigmat = SigMat(raw=sig0raw, code=SigTwoDex.Ed25519, index=index)
    assert txsigmat.qb64 == 'AAQ29m1nz43THJK99M6coPmJ7rwRvHsje4HKARYLRXfDGufqy6FpkdlxSs5-uDvqP5XEuU-p9dvzFKqn9kD7hIDA'
    assert len(txsigmat.qb64) == 88
    assert txsigmat.index == index

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 352  #  264 + 88

    #  Recieve side
    rxsrdr = Serder(raw=msgb)
    assert rxsrdr.size == txsrdr.size
    assert rxsrdr.ked == ked0

    rxsigqb64 = msgb[rxsrdr.size:].decode("utf-8")
    assert len(rxsigqb64) == len(txsigmat.qb64)
    rxsigmat = SigMat(qb64=rxsigqb64)
    assert rxsigmat.index == index

    rxaidqb64 = rxsrdr.ked["aid"]
    rxaidmat = CryMat(qb64=rxaidqb64)
    assert rxaidmat.qb64 == aidmat.qb64
    assert rxaidmat.code == CryOneDex.Ed25519

    rxverqb64 = rxsrdr.ked["keys"][index]
    rxvermat = CryMat(qb64=rxverqb64)
    assert rxvermat.qb64 == rxaidmat.qb64  #  basic derivation same

    indexes = [ int(index, 16) for index in rxsrdr.ked["idxs"]]
    assert indexes == [0]
    assert indexes[0] == rxsigmat.index

    result = pysodium.crypto_sign_verify_detached(rxsigmat.raw, rxsrdr.raw, rxvermat.raw)
    assert not result  # None if verifies successfully else raises ValueError
    """ Done Test """


if __name__ == "__main__":
    test_keyeventsequence_1()