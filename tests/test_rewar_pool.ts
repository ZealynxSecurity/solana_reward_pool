import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TestRewarPool } from "../target/types/reward_pool";
import { findProgramAddressSync } from "@project-serum/anchor/dist/cjs/utils/pubkey";
import { assert } from "chai";

// // Airdrop function
// async function airdrop(connection, pubkey) {
//   const airdropSignature = await connection.requestAirdrop(pubkey, 1e9); // 1 SOL
//   await connection.confirmTransaction(airdropSignature, "confirmed");
// }

// // describe("test_rewar_pool", () => {
// //   const provider = anchor.AnchorProvider.local("http://127.0.0.1:8899");
// //   anchor.setProvider(provider);

// //   const connection = provider.connection;
// //   const wallet = provider.wallet;
// //   const walletFake = anchor.web3.Keypair.generate();
// //   const program = anchor.workspace.TestRewarPool as Program<TestRewarPool>;
// //   const vault = anchor.web3.Keypair.generate();
// //   const [tokenPDA] = findProgramAddressSync(
// //     [Buffer.from("token")],
// //     program.programId
// //   );

// //   it("Initializes the reward pool", async () => {
// //     // Airdrop to the wallet
// //     await airdrop(connection, wallet.publicKey);

// //     const [rewardPoolPda] = await anchor.web3.PublicKey.findProgramAddress(
// //       [Buffer.from("reward_pool")],
// //       program.programId
// //     );

// //     await program.methods
// //       .initialize()
// //       .accounts({
// //         rewardPool: rewardPoolPda,
// //         user: wallet.publicKey,
// //         systemProgram: anchor.web3.SystemProgram.programId,
// //       })
// //       .signers([vault])
// //       .rpc({ commitment: "confirmed" });

// //     // const rewardPoolAccount = await program.account.rewardPoolState.fetch(rewardPoolPda);
// //     // assert.strictEqual(
// //     //   rewardPoolAccount.owner.toBase58(),
// //     //   wallet.publicKey.toBase58()
// //     // );
// //   });
// // });
