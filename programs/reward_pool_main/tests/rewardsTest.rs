// use anchor_lang::prelude::*;
// use anchor_spl::token::{self, Token, TokenAccount, Transfer};
// use solana_program::{pubkey::Pubkey, instruction::Instruction};
// use solana_program_test::*;
// use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};
// use reward_pool::{RewardPoolState, RewardInfo, id, entry, Initialize};
// use tokio::{task, time};

// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_initialize() {
//         let program_id = id();
//         let mut program_test = ProgramTest::new("reward_pool", program_id, |pubkey, accounts, _| {
//             entry(pubkey, accounts, &[])
//         });

//         let user = Keypair::new();
//         let reward_pool_pubkey = Pubkey::find_program_address(&[b"reward_pool"], &program_id).0;

//         let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

//         // Construir la lista de cuentas
//         let accounts = vec![
//             AccountMeta::new(reward_pool_pubkey, false),
//             AccountMeta::new(user.pubkey(), true),
//             AccountMeta::new_readonly(solana_program::system_program::ID, false),
//         ];

//         // Serializar la instrucción para `initialize`
//         let initialize_instruction = Initialize {};

//         let instruction_data = anchor_lang::InstructionData::data(&initialize_instruction);

//         // Crear la instrucción completa
//         let instruction = Instruction {
//             program_id,
//             accounts,
//             data: instruction_data,
//         };

//         // Crear la transacción
//         let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
//         transaction.sign(&[&user, &payer], recent_blockhash);

//         // Ejecutar la transacción
//         banks_client.process_transaction(transaction).await.unwrap();

//         // Verificar el estado de la cuenta `RewardPool`
//         let reward_pool_account = banks_client
//             .get_account(reward_pool_pubkey)
//             .await
//             .expect("get_account")
//             .expect("reward_pool_account not found");
//         let reward_pool_state = RewardPoolState::try_from_slice(&reward_pool_account.data).expect("failed to deserialize");

//         // Validar el propietario
//         assert_eq!(reward_pool_state.owner, user.pubkey());
//     }
// }
