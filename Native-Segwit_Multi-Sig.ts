import * as bitcoin from "bitcoinjs-lib";

const network = bitcoin.networks.testnet; // Otherwise, bitcoin = mainnet and regnet = local

export async function createNativeSegwit(
  originPubkeys: string[], // Singer pubkeys list
  threshold: number // Number of Co-Signers
) {
  try {
    const hexedPubkeys = originPubkeys.map((pubkey) =>
      Buffer.from(pubkey, "hex")
    );
    const p2ms = bitcoin.payments.p2ms({
      m: parseInt(threshold.toString()),
      pubkeys: hexedPubkeys,
      network,
    });
    const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network });

    return {
      success: true,
      message: "Create Musig Wallet successfully.",
      payload: {
        address: p2wsh.address,
      },
    };
  } catch (error: any) {
    console.log("error in creating segwit address ==> ", error);
    return {
      success: false,
      message: "There is something error",
      payload: null,
    };
  }
}
