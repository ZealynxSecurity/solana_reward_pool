import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { RewardPoolMain } from "../target/types/reward_pool_main";
import { assert } from "chai";

// Airdrop function
async function airdrop(connection, pubkey) {
  const airdropSignature = await connection.requestAirdrop(pubkey, 1e9); // 1 SOL
  await connection.confirmTransaction(airdropSignature, "confirmed");
}

describe("reward_pool_main", () => {
  const provider = anchor.AnchorProvider.local("http://127.0.0.1:8899");
  anchor.setProvider(provider);

  const connection = provider.connection;
  const wallet = provider.wallet;
  const walletFake = anchor.web3.Keypair.generate();
  const program = anchor.workspace.RewardPoolMain as Program<RewardPoolMain>;
  const vault = anchor.web3.Keypair.generate();


  it("Initializes the reward pool", async () => {
    // Airdrop to the wallet
    await airdrop(connection, wallet.publicKey);

    const [tokenPDA] = await anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("token")],
      program.programId
    );
    const [rewardPoolPda] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from("reward_pool")],
      program.programId
    );

    // await program.methods
    //   .initialize()
    //   .accounts({
    //     rewardPool: rewardPoolPda,
    //     user: wallet.publicKey,
    //     systemProgram: anchor.web3.SystemProgram.programId,
    //   })
    //   .signers([vault])
    //   .rpc({ commitment: "confirmed" });

    // const rewardPoolAccount = await program.account.rewardPoolState.fetch(rewardPoolPda);
    // assert.strictEqual(
    //   rewardPoolAccount.owner.toBase58(),
    //   wallet.publicKey.toBase58()
    // );
  });
});
