use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use sha3::{Digest, Keccak256};
use solana_program::{pubkey::Pubkey, system_program};

declare_id!("44cUoDQ2V5GH5zgaYD7A3EMgRCnWXRGvfCgGkEUxxYWS");

#[program]
pub mod reward_pool {
    use super::*;
    use crate::func_visibility::deposit_private_function;
    use crate::func_visibility::claim_private_function;
    use crate::func_visibility::withdraw_private_function;

    pub fn initialize(ctx: Context<Initialize>, signer_pubkey: Pubkey) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authorized_signer = signer_pubkey;
        pool.tax_recipient = *ctx.accounts.user.to_account_info().key;
        Ok(())
    }

    pub fn verify_signature(ctx: Context<VerifySignature>, data: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        if utils::verify_signature(&data, &signature, ctx.accounts.signer.key) {
            msg!("Hash verified successfully!");
            Ok(())
        } else {
            Err(ErrorCode::SignatureVerificationFailed.into())
        }
    }

    pub fn process_payment(ctx: Context<PaymentContext>, amount: u64) -> Result<()> {
        if amount < 10000000 {
            return Err(ErrorCode::PaymentAmountTooLow.into());
        }
        msg!("Payment processed successfully!");
        Ok(())
    }

    //public
    pub fn deposit_reward(ctx: Context<DepositReward>, campaign_id: u64, campaign_amount: u64, fee_amount: u64, signature: Vec<u8>) -> Result<()> {
        deposit_private_function::_deposit_reward(ctx, campaign_id, campaign_amount, fee_amount, signature)?;
        Ok(())
    }


    pub fn claim_reward(ctx: Context<ClaimReward>, campaign_id: u64, amount: u64, signature: Vec<u8>) -> Result<()> {
        claim_private_function::_claim_reward(ctx, campaign_id, amount, signature)?;
        Ok(())
    }

    // WITHDRAW
    pub fn withdraw_reward_pool(ctx: Context<WithdrawRewardPool>, campaign_id: u64, amount: u64, signature: Vec<u8>) -> Result<()> {
        withdraw_private_function::_withdraw_reward_pool(ctx, campaign_id, amount, signature)?;
        Ok(())
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        ctx.accounts.admin_account.paused = true;
        Ok(())
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        ctx.accounts.admin_account.paused = false;
        Ok(())
    }

    pub fn set_authorized_signer(ctx: Context<SetAuthorizedSigner>, new_signer: Pubkey) -> Result<()> {
        if new_signer == Pubkey::default() {
            return Err(ErrorCode::InvalidSignerAddress.into());
        }
        // require!(new_signer != Pubkey::default(), MyError::InvalidSignerAddress);
        ctx.accounts.admin_account.authorized_signer = new_signer;
        Ok(())
    }
    
    pub fn set_tax_recipient(ctx: Context<SetTaxRecipient>, new_tax_recipient: Pubkey) -> Result<()> {
        if new_tax_recipient == Pubkey::default() {
            return Err(ErrorCode::CannotBeTheZeroAddress.into());
        }
        // require!(new_tax_recipient != Pubkey::default(), MyError::InvalidAddress);
        ctx.accounts.reward_pool.tax_recipient = new_tax_recipient;
        Ok(())
    }

    pub fn get_claimed_amount(ctx: Context<GetClaimedAmount>, claimant: Pubkey) -> Result<u64> {
        let claims = &ctx.accounts.campaign_account.claims;
        let total_claimed = claims.iter()
            .filter(|claim| claim.claimant == claimant)
            .map(|claim| claim.amount)
            .sum();
        
        if total_claimed == 0 {
            return Err(error!(ErrorCode::NoClaimsFound));
        }
    
        Ok(total_claimed)
    }
    
    
}

pub mod func_visibility {

    pub mod deposit_private_function {
        use super::super::*;

        //Private
        pub (crate) fn _deposit_reward(
            ctx: Context<DepositReward>, 
            campaign_id: u64, 
            campaign_amount: u64, 
            fee_amount: u64, 
            signature: Vec<u8>
        ) -> Result<()> {
            let accounts = ctx.accounts;
            if accounts.admin_account.paused {
                return Err(ErrorCode::ProgramPaused.into());
            }
        
            // let balance_before = accounts.token_account.amount;
            let balance_before = accounts.token_account.amount;

        
            let message = accounts.token_account.to_account_info().key.to_bytes() // tokenAddress
                .iter()
                .chain(&accounts.from.key().to_bytes()) // msg.sender
                .chain(&campaign_id.to_le_bytes()) // campaignId
                .chain(&campaign_amount.to_le_bytes()) // campaignAmount
                .chain(&fee_amount.to_le_bytes()) // feeAmount
                .chain(&ctx.program_id.to_bytes()) // address(this)
                .copied()
                .collect::<Vec<u8>>();

            let message_hash = Keccak256::digest(&message); //@audit => mapping
            let eth_signed_message_hash = utils::prepare_eth_signed_message(&message_hash);
        
            if accounts.admin_account.used_signatures.iter().any(|record| record.signature == signature && record.used) {
                return Err(ErrorCode::SignatureAlreadyUsed.into());
            }

            accounts.admin_account.used_signatures.push(SignatureRecord { signature: signature.clone(), used: true });

            // if !utils::verify_signature(&eth_signed_message_hash, &signature, &accounts.authorized_signer.key) {
            //     return Err(ErrorCode::InvalidSignature.into());
            // }

            let (campaign_account_pda, bump_seed) = Pubkey::find_program_address(
                &[
                    b"campaign",
                    &accounts.token_account.mint.to_bytes(),
                    &campaign_id.to_le_bytes(),
                ],
                &ctx.program_id,
            );

            if campaign_account_pda != accounts.campaign_account.key() {
                return Err(ErrorCode::InvalidCampaignAccount.into());
            }

            if accounts.campaign_account.token_address != Pubkey::default() {
                return Err(ErrorCode::CampaignAlreadyExists.into());
            }

            let cpi_program = accounts.token_program.to_account_info();

            let cpi_accounts_fee = Transfer {
                from: accounts.from.to_account_info(),
                to: accounts.tax_recipient.to_account_info(),
                authority: accounts.authorized_signer.to_account_info(),
            };
            let cpi_context_fee = CpiContext::new(cpi_program.clone(), cpi_accounts_fee);
            token::transfer(cpi_context_fee, fee_amount)?;

            let cpi_accounts_campaign = Transfer {
                from: accounts.from.to_account_info(),
                to: accounts.token_account.to_account_info(),
                authority: accounts.authorized_signer.to_account_info(),
            };
            let cpi_context_campaign = CpiContext::new(cpi_program, cpi_accounts_campaign);
            token::transfer(cpi_context_campaign, campaign_amount)?;

            // let balance_after = accounts.token_account.amount;
            let balance_after = accounts.token_account.amount;

            let actual_amount_deposited = balance_after.wrapping_sub(balance_before);

            if actual_amount_deposited != campaign_amount {
                return Err(ErrorCode::DepositAmountMismatch.into());
            }

            accounts.campaign_account.amount = campaign_amount;
            accounts.campaign_account.token_address = accounts.token_account.mint;
            accounts.campaign_account.owner_address = *accounts.from.key;

            emit!(RewardDeposited {
                from: *accounts.from.key,
                amount: campaign_amount,
                campaign_id: campaign_id
            });

            Ok(())
        }
    }


    pub mod claim_private_function {
        use super::super::*;

        //Private
        pub (crate) fn _claim_reward(
            ctx: Context<ClaimReward>, 
            campaign_id: u64, 
            amount: u64, 
            signature: Vec<u8>
        ) -> Result<()> {
            //Pause
            let accounts = ctx.accounts;
            if accounts.admin_account.paused {
                return Err(ErrorCode::ProgramPaused.into());
            }

            let balance_before = accounts.token_account.amount;

        
            // MessageHash
            let message = accounts.from.key().to_bytes() // msg.sender
                .iter()
                .chain(&campaign_id.to_le_bytes()) // campaignId
                .chain(&amount.to_le_bytes()) // amount
                .chain(&ctx.program_id.to_bytes()) // address(this)
                .copied()
                .collect::<Vec<u8>>();

            //require signature alredy used
            let message_hash = Keccak256::digest(&message);
            let eth_signed_message_hash = utils::prepare_eth_signed_message(&message_hash);

            if accounts.admin_account.used_signatures.iter().any(|record| record.signature == signature && record.used) {
                return Err(ErrorCode::SignatureAlreadyUsed.into());
            }
            //usedSignatures[ethSignedMessageHash] = true;
            accounts.admin_account.used_signatures.push(SignatureRecord { signature: signature.clone(), used: true });

            // @audit => Invalid signature => no necesario
            // if !utils::verify_signature(&eth_signed_message_hash, &signature, &accounts.authorized_signer.key) {
            //     return Err(ErrorCode::InvalidSignature.into());
            // }

            if accounts.campaign_account.amount > amount {
                return Err(ErrorCode::NotEnoughRewardInThePool.into());
            }
            //==========================
            //require(info.claimed[msg.sender] == 0, "Already claimed"); @audit=> mapping
            if let Some(claim_record) = accounts.campaign_account.claims.iter().find(|c| c.claimant == accounts.from.key()) {
                
                // Asegurar que el usuario no reclame más de una vez
                if claim_record.amount > 0 {
                    return Err(ErrorCode::AlreadyClaimed.into());
                }
                // Si el usuario ya ha reclamado, verificar que no exceda el saldo permitido con esta nueva reclamación
                if claim_record.amount + amount > accounts.campaign_account.amount {
                    return Err(ErrorCode::ClaimAmountExceedsAllowedBalance.into());
                }
                
            }
            
            // Si no hay registros previos o si el reclamo previo es 0 (aunque este caso no debería ocurrir según la lógica actual),
            // procedemos a registrar el nuevo reclamo y disminuir el monto disponible
            accounts.campaign_account.claims.push(ClaimRecord {
                claimant: accounts.from.key(),
                amount,
            });
            // Disminuir la cantidad total disponible en la campaña
            accounts.campaign_account.amount -= amount;
            //==========================
            

            //TRANSFER
            // Configuración para la instrucción CPI (Cross-Program Invocation) de transferencia
            let cpi_accounts = Transfer {
            from: accounts.from.to_account_info(), // La cuenta 'from' debe ser un TokenAccount
            to: accounts.tax_recipient.to_account_info(),
            authority: accounts.authorized_signer.to_account_info(),
            };
            // Configuración separada para el programa CPI
            let cpi_program = accounts.token_program.to_account_info();
            let cpi_context = CpiContext::new(cpi_program, cpi_accounts);

            // Realizar la transferencia
            token::transfer(cpi_context, amount)?;

            let balance_after = accounts.token_account.amount;

            // Calcular la cantidad de tokens transferidos realmente
            let actual_amount_transferred = balance_after.checked_sub(balance_before).unwrap_or_default();

            // Verificar si la cantidad transferida coincide con la cantidad esperada
            if actual_amount_transferred != amount {
            return Err(ErrorCode::ActualTransferMismatch.into());
            }

            emit!(ClaimRewardEvent {
                from: *accounts.from.key,
                amount: amount,
                campaign_id: campaign_id
            });

            Ok(())
        }
    }

    pub mod withdraw_private_function {
        use super::super::*;

        //Private
        pub (crate) fn _withdraw_reward_pool(
            ctx: Context<WithdrawRewardPool>,
            campaign_id: u64,
            amount: u64,
            signature: Vec<u8>
        ) -> Result<()> {
            //Pause
            let accounts = ctx.accounts;
            if accounts.admin_account.paused {
                return Err(ErrorCode::ProgramPaused.into());
            }

            //MessageHash
            let message = accounts.from.key().to_bytes() //msg.sender
            .iter()
            .chain(&campaign_id.to_le_bytes()) // campaign_id
            .chain(&amount.to_le_bytes()) // amount
            .copied()
            .collect::<Vec<u8>>();

            let message_hash = Keccak256::digest(&message);
            let eth_signed_message_hash = utils::prepare_eth_signed_message(&message_hash);

            // require signature alredy used
            if accounts.admin_account.used_signatures.iter().any(|record| record.signature == signature && record.used) {
                return Err(ErrorCode::SignatureAlreadyUsed.into());
            }
            //usedSignatures[ethSignedMessageHash] = true;
            accounts.admin_account.used_signatures.push(SignatureRecord {signature: signature.clone(), used: true});

            // @audit => Invalid signature => no necesario
            // if !utils::verify_signature(&eth_signed_message_hash, &signature, &accounts.authorized_signer.key) {
            //     return Err(ErrorCode::InvalidSignature.into());
            // }

            if accounts.campaign_account.amount > amount {
                return Err(ErrorCode::NotEnoughRewardInThePool.into());
            }
            //==========================
            //require(info.claimed[msg.sender] == 0, "Already claimed"); @audit=> mapping
            if let Some(claim_record) = accounts.campaign_account.claims.iter().find(|c| c.claimant == accounts.from.key()) {
                if claim_record.amount > 0 {
                    return Err(ErrorCode::AlreadyClaimed.into());
                }
                if  *accounts.from.key != accounts.campaign_account.owner_address {
                    return Err(ErrorCode::OnlyCampaignCreatorAllowed.into());
                }   
            }

            // Disminuir la cantidad total disponible en la campaña
            accounts.campaign_account.amount -= amount;

            //TRANSFER
            let cpi_accounts = Transfer {
            from: accounts.from.to_account_info(), // La cuenta 'from' debe ser un TokenAccount
            to: accounts.tax_recipient.to_account_info(),
            authority: accounts.authorized_signer.to_account_info(),
            };

            // Configuración separada para el programa CPI
            let cpi_program = accounts.token_program.to_account_info();
            let cpi_context = CpiContext::new(cpi_program, cpi_accounts);

            // Realizar la transferencia
            token::transfer(cpi_context, amount)?;

            emit!(WithdrawReward {
                from: *accounts.from.key,
                amount: amount,
                campaign_id: campaign_id
            });

            Ok(())

        }
    } 

    
}

pub mod utils {
    use sha3::{Digest, Keccak256};
    use solana_program::pubkey::Pubkey;

    pub fn verify_signature(data: &[u8], signature: &[u8], signer_pubkey: &Pubkey) -> bool {
        let hashed_data = Keccak256::digest(data);
        hashed_data.as_slice() == signature
    }

    pub fn prepare_eth_signed_message(message_hash: &[u8]) -> Vec<u8> {
        let prefix = b"\x19Ethereum Signed Message:\n32";
        Keccak256::digest(&[prefix, message_hash].concat()).to_vec()
    }
}


////////////////////////////
/// EVENT
////////////////////////////

#[event]
pub struct RewardDeposited {
    pub from: Pubkey,
    pub amount: u64,
    pub campaign_id: u64,
}
#[event]
pub struct ClaimRewardEvent {
    pub from: Pubkey,
    pub amount: u64,
    pub campaign_id: u64,
}
#[event]
pub struct WithdrawReward {
    pub from: Pubkey,
    pub amount: u64,
    pub campaign_id: u64,
}

////////////////////////////
/// ACCOUNT
////////////////////////////

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8000)]
    pub pool: Account<'info, RewardPoolState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

//@audit=> necesario?
#[derive(Accounts)]
pub struct VerifySignature<'info> {
    pub signer: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct PaymentContext<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    #[account(mut)]
    pub to: Account<'info, RewardPoolState>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct RewardPoolState {
    pub authorized_signer: Pubkey,
    pub tax_recipient: Pubkey,
    pub reward_infos: Vec<RewardInfo>,
    pub used_signatures: Vec<SignatureRecord>,
}

//Function
#[derive(Accounts)]
pub struct DepositReward<'info> {
    #[account(mut)]
    pub from: Signer<'info>,  // The account from which tokens will be transferred
    #[account(mut)]
    pub tax_recipient: Account<'info, TokenAccount>,  // The account to receive the tax fee
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,  // The account holding tokens for the contract
    #[account(mut)]
    pub admin_account: Account<'info, AdminAccount>,  // Admin account for additional checks
    #[account(mut)]
    pub campaign_account: Account<'info, CampaignReward>,  // Account to manage campaign details
    pub authorized_signer: AccountInfo<'info>,  // The signer authorized to perform transactions
    pub token_program: Program<'info, Token>,  // The token program used for SPL Token transactions
    pub system_program: Program<'info, System>,  // System program
}

//Function
#[derive(Accounts)]
pub struct ClaimReward<'info> {
    #[account(mut)]
    pub from: Signer<'info>,  // The user claiming the reward
    #[account(mut)]
    pub tax_recipient: Account<'info, TokenAccount>,  // The account to receive any potential fees (if applicable)
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,  // The account holding tokens for the contract
    #[account(mut)]
    pub admin_account: Account<'info, AdminAccount>,  // Admin account for additional checks
    #[account(mut)]
    pub campaign_account: Account<'info, CampaignReward>,  // Account to manage campaign details
    pub authorized_signer: AccountInfo<'info>,  // The signer authorized to perform transactions
    pub token_program: Program<'info, Token>,  // The token program used for SPL Token transactions
    pub system_program: Program<'info, System>,  // System program
}
//Function
#[derive(Accounts)]
pub struct WithdrawRewardPool<'info> {
    #[account(mut)]
    pub from: Signer<'info>,  // The user claiming the reward
    #[account(mut)]
    pub tax_recipient: Account<'info, TokenAccount>,  // The account to receive any potential fees (if applicable)
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,  // The account holding tokens for the contract
    #[account(mut)]
    pub admin_account: Account<'info, AdminAccount>,  // Admin account for additional checks
    #[account(mut)]
    pub campaign_account: Account<'info, CampaignReward>,  // Account to manage campaign details
    pub authorized_signer: AccountInfo<'info>,  // The signer authorized to perform transactions
    pub token_program: Program<'info, Token>,  // The token program used for SPL Token transactions
    pub system_program: Program<'info, System>,  // System program
}

#[account]
pub struct AdminAccount {
    pub paused: bool,
    pub used_signatures: Vec<SignatureRecord>, // Manage used signatures
    pub authorized_signer: Pubkey,  // Agregar este campo

}
//===========================================
#[derive(Accounts)]
pub struct SetAuthorizedSigner<'info> {
    #[account(mut, has_one = authorized_signer)]
    pub admin_account: Account<'info, AdminAccount>,
    pub authorized_signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetTaxRecipient<'info> {
    #[account(mut, has_one = authorized_signer)]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub authorized_signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(mut, has_one = authorized_signer)]
    pub admin_account: Account<'info, AdminAccount>,
    pub authorized_signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut, has_one = authorized_signer)]
    pub admin_account: Account<'info, AdminAccount>,
    pub authorized_signer: Signer<'info>,
}
#[derive(Accounts)]
pub struct GetClaimedAmount<'info> {
    pub campaign_account: Account<'info, CampaignReward>,
}

//===========================================

#[account]
pub struct CampaignReward {
    pub token_address: Pubkey,
    pub amount: u64,
    pub owner_address: Pubkey,
    pub claims: Vec<ClaimRecord>, //@audit => new
}

////////////////////////////
/// AnchorSerialize, AnchorDeserialize, Clone
////////////////////////////

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RewardInfo {
    pub amount: u64,
    pub token_address: Pubkey,
    pub owner_address: Pubkey,
    pub claimed: Vec<ClaimRecord>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ClaimRecord {
    pub claimant: Pubkey,
    pub amount: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SignatureRecord {
    pub signature: Vec<u8>,
    pub used: bool,
}

////////////////////////////
/// ERROR
////////////////////////////

#[error_code]
pub enum ErrorCode {
    #[msg("The provided signature does not match the message or the signer.")]
    SignatureVerificationFailed,
    #[msg("The payment amount is too low.")]
    PaymentAmountTooLow,
    #[msg("The program is paused.")]
    ProgramPaused,
    #[msg("Signature already used.")]
    SignatureAlreadyUsed,
    #[msg("Invalid signature.")]
    InvalidSignature,
    #[msg("Campaign already exists.")]
    CampaignAlreadyExists,
    #[msg("Actual deposit does not match expected.")]
    DepositAmountMismatch, // New error code for deposit amount mismatch
    #[msg("Not enough reward in the pool")]
    NotEnoughRewardInThePool, 
    #[msg("Not enough reward in the pool")]
    ClaimAmountExceedsAllowedBalance, 
    #[msg("Already claimed")]
    AlreadyClaimed, 
    #[msg("Actual transfer does not match expected")]
    ActualTransferMismatch, 
    #[msg("Invalid signer address")]
    InvalidSignerAddress, 
    #[msg("Invalid address: cannot be the zero address")]
    CannotBeTheZeroAddress, 
    #[msg("No claims found for the provided claimant.")]
    NoClaimsFound,
    #[msg("Only campaign creator allowed")]
    OnlyCampaignCreatorAllowed,
    #[msg("Invalid Campaign Account")]
    InvalidCampaignAccount,

}

