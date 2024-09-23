import * as bitcoin from "bitcoinjs-lib";
import { LEAF_VERSION_TAPSCRIPT } from "bitcoinjs-lib/src/payments/bip341";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
import BIP32Factory from "bip32";
import * as ecc from "tiny-secp256k1";
import { TaprootMultisigWallet } from "utils/mutisigWallet";

const rng = require("randombytes");
const bip32 = BIP32Factory(ecc);

export const createTaprootMultisig = async (
  pubkeyList: string[], // Singer pubkeys list
  threshold: number // Number of Co-Signers
) => {
  try {
    const leafPubkeys: Buffer[] = pubkeyList.map((pubkey: string) =>
      toXOnly(Buffer.from(pubkey, "hex"))
    );

    const leafKey = bip32.fromSeed(rng(64), bitcoin.networks.testnet);

    const multiSigWallet = new TaprootMultisigWallet(
      leafPubkeys,
      threshold * 1,
      leafKey.privateKey!,
      LEAF_VERSION_TAPSCRIPT
    ).setNetwork(bitcoin.networks.testnet);

    console.log("address ==> ", multiSigWallet.address);

    return {
      success: true,
      message: "Create Musig Wallet successfully.",
      payload: {
        address: multiSigWallet.address,
      },
    };
  } catch (error: any) {
    return {
      success: false,
      message: "There is something error",
      payload: null,
    };
  }
};
