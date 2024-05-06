use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use solana_program::pubkey::Pubkey;

declare_id!("Fg6PaFyL1JpZ5eXdiKxzg1D4d2tfnTVMMk2xVZ7JvA9D");

#[program]
pub mod reward_pool_main {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let reward_pool = &mut ctx.accounts.reward_pool;
        reward_pool.tax_recipient = ctx.accounts.user.key();
        reward_pool.owner = ctx.accounts.user.key();
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn deposit_reward(
        ctx: Context<DepositReward>, 
        token_address: Pubkey, 
        campaign_amount: u64,
        fee_amount: u64,
        campaign_id: u64
    ) -> Result<()> {
        // Logic for depositing rewards
        let reward_info = &mut ctx.accounts.reward_info;
        let reward_pool = &mut ctx.accounts.reward_pool;

        if reward_pool.paused {
            return Err(ErrorCode::ProgramPaused.into());
        }
        
        // Ensure the campaign is new by checking if token_address is default (indicating uninitialized)
        if reward_info.token_address != Pubkey::default() {
            return Err(ErrorCode::CampaignAlreadyExists.into());
        }

        // Perform the token transfer for the fee
        let transfer_fee_ix = Transfer {
            from: ctx.accounts.user.to_account_info(),
            to: ctx.accounts.tax_recipient_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_fee_ix
            ),
            fee_amount,
        )?;

        // Perform the token transfer for the campaign amount to the campaign's token account
        let transfer_campaign_ix = Transfer {
            from: ctx.accounts.user.to_account_info(),
            to: ctx.accounts.campaign_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_campaign_ix
            ),
            campaign_amount,
        )?;
        
        // Initialize or update reward_info
        reward_info.token_address = token_address;
        reward_info.amount += campaign_amount; // Assuming accumulation of amounts if multiple deposits
        reward_info.owner_address = *ctx.accounts.user.key;

        Ok(())
    }

    #[allow(unused_variables)]
    pub fn claim_reward(
        ctx: Context<ClaimReward>, 
        campaign_id: u64, 
        amount: u64
    ) -> Result<()> {
        // Logic for claiming rewards
        let reward_info = &mut ctx.accounts.reward_info;
        let reward_pool = &mut ctx.accounts.reward_pool;

        if reward_pool.paused {
            return Err(ErrorCode::ProgramPaused.into());
        }
        // Ensure there is enough reward in the pool
        if reward_info.amount < amount {
            return Err(ErrorCode::NotEnoughReward.into());
        }

        // Claim amount does not exceed allowed balance
        let amount_claimed = &mut ctx.accounts.amount_claimed;
        
        if amount_claimed.amount_claimed == 0 {
            return Err(ErrorCode::RewardAlreadyClaimed.into());
        }

        if amount_claimed.amount_claimed + amount > reward_info.amount {
            return Err(ErrorCode::ClaimAmountExceedsAllowedBalance.into());
        }

        amount_claimed.amount_claimed += amount;
        reward_info.amount -= amount;

        // Transfer the reward to the user's token account
        let transfer_reward_ix = Transfer {
            from: ctx.accounts.campaign_token_account.to_account_info(),
            to: ctx.accounts.user.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_reward_ix
            ),
            amount,
        )?;

        Ok(())
    }

    #[allow(unused_variables)]
    pub fn withdraw_reward(
        ctx: Context<WithdrawReward>, 
        campaign_id: u64, 
        amount: u64
    ) -> Result<()> {
        // Logic for withdrawing rewards
        let reward_info = &mut ctx.accounts.reward_info;
        let reward_pool = &mut ctx.accounts.reward_pool;

        if reward_pool.paused {
            return Err(ErrorCode::ProgramPaused.into());
        }

        if reward_info.amount < amount {
            return Err(ErrorCode::NotEnoughReward.into());
        }

        // Only campaign creator allowed to withdraw
        if *ctx.accounts.user.key != reward_info.owner_address {
            return Err(ErrorCode::OnlyCampaignCreatorAllowed.into());
        }

        reward_info.amount -= amount;

        // Perform the token transfer from the campaign account to the user token account
        let transfer_reward_ix = Transfer {
            from: ctx.accounts.campaign_token_account.to_account_info(),
            to: ctx.accounts.user.to_account_info(), 
            authority: ctx.accounts.user.to_account_info(),
        };

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_reward_ix
            ),
            amount,
        )?;

        Ok(())
    }

    #[allow(unused_variables)]
    pub fn get_claimed_amount(
        ctx: Context<GetClaimedAmount>,
        campaign_id: u64,
    ) -> Result<u64> {
        let amount_claimed = &ctx.accounts.amount_claimed;
        Ok(amount_claimed.amount_claimed)
    }

    pub fn set_authorized_signer(ctx: Context<SetAuthorizedSigner>, new_signer: Pubkey) -> Result<()> {
        if ctx.accounts.owner.key() != ctx.accounts.reward_pool.authorized_signer {
            return Err(ErrorCode::Unauthorized.into());
        }

        if new_signer == Pubkey::default() {
            return Err(ErrorCode::InvalidOwnerAddress.into());
        }

        ctx.accounts.reward_pool.authorized_signer = new_signer;
        msg!("Authorized signer changed to: {}", new_signer);
        Ok(())
    }

    pub fn set_tax_recipient(ctx: Context<SetTaxRecipient>, new_tax_recipient: Pubkey) -> Result<()> {
        if new_tax_recipient == Pubkey::default() {
            return Err(ErrorCode::InvalidOwnerAddress.into());
        }

        ctx.accounts.reward_pool.tax_recipient = new_tax_recipient;
        msg!("Tax recipient changed to: {}", new_tax_recipient);
        Ok(())
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        ctx.accounts.reward_pool.paused = true;
        msg!("Reward pool paused");
        Ok(())
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        ctx.accounts.reward_pool.paused = false;
        msg!("Reward pool unpaused");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {    
    #[account(
        init, 
        payer = user, 
        space = 8 + 8 + 32 + 32)]
    pub reward_pool: Account<'info, RewardPoolState>,
    
    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct RewardPoolState {
    pub owner: Pubkey,
    pub tax_recipient: Pubkey,
    pub authorized_signer: Pubkey,
    pub paused: bool,
}

#[account]
pub struct RewardInfo {
    pub amount: u64,
    pub token_address: Pubkey,
    pub owner_address: Pubkey,
}

#[account]
pub struct AmountClaimed {
    pub amount_claimed: u64,
}

#[derive(Accounts)]
#[instruction(campaign_id: u64)]
pub struct DepositReward<'info> {
    #[account(mut)]
    pub reward_pool: Account<'info, RewardPoolState>,

    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub tax_recipient_account: Account<'info, TokenAccount>, // Tax recipient's token account
    #[account(mut)]
    pub campaign_token_account: Account<'info, TokenAccount>, // Token account to store the campaign's funds
    pub token_program: Program<'info, Token>,  // Token program
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"reward_info", campaign_id.to_le_bytes().as_ref()],
        bump,
        space = 8 + 32 + 32 + 8 // Assuming space for u64 (amount), 2 * Pubkey (token_address, owner_address), plus discriminator
    )]
    pub reward_info: Account<'info, RewardInfo>, // Assumes reward_info is initialized here if not already existing
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(campaign_id: u64)]
pub struct ClaimReward<'info> {
    #[account(mut)]
    pub reward_pool: Account<'info, RewardPoolState>,

    #[account(
        init_if_needed,
        payer = user,
        space = 8 + 8,
        seeds = [b"amount_claimed", user.key().as_ref(), campaign_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub amount_claimed: Account<'info, AmountClaimed>,

    #[account(
        mut,
        seeds = [b"reward_info", campaign_id.to_le_bytes().as_ref()],
        bump
    )]
    pub reward_info: Account<'info, RewardInfo>,

    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub campaign_token_account: Account<'info, TokenAccount>, // Token account to store the campaign's funds
    pub token_program: Program<'info, Token>,  // Token program
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(campaign_id: u64)]
pub struct WithdrawReward<'info> {
    #[account(mut)]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub user: Signer<'info>,
    #[account(mut)]
    pub campaign_token_account: Account<'info, TokenAccount>, // Token account to store the campaign's funds
    pub token_program: Program<'info, Token>,  // Token program
    #[account(
        mut,
        seeds = [b"reward_info", campaign_id.to_le_bytes().as_ref()],
        bump
    )]
    pub reward_info: Account<'info, RewardInfo>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(campaign_id: u64)]
pub struct GetClaimedAmount<'info> {
    #[account(
        seeds = [b"amount_claimed", campaign_id.to_le_bytes().as_ref(), user.key().as_ref()],
        bump
    )]
    pub amount_claimed: Account<'info, AmountClaimed>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetAuthorizedSigner<'info> {
    #[account(
        mut,
        has_one = owner, // @audit should it be the owner or the authorized_signer?
    )]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetTaxRecipient<'info> {
    #[account(
        mut,
        has_one = owner,
    )]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(
        mut,
        has_one = owner,
    )]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(
        mut,
        has_one = owner,
    )]
    pub reward_pool: Account<'info, RewardPoolState>,
    pub owner: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("The campaign already exists.")]
    CampaignAlreadyExists,
    #[msg("Not enough reward in the pool.")]
    NotEnoughReward,
    #[msg("Claim amount exceeds allowed balance")]
    ClaimAmountExceedsAllowedBalance,
    #[msg("Reward already claimed")]
    RewardAlreadyClaimed,
    #[msg("Only campaign creator allowed to withdraw")]
    OnlyCampaignCreatorAllowed,
    #[msg("Invalid signer address")]
    InvalidSignerAddress,
    #[msg("Invalid owner address")]
    InvalidOwnerAddress,
    #[msg("Program is paused")]
    ProgramPaused,
    #[msg("Unauthorized")]
    Unauthorized,
}