use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/option
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId, policies, quantity_of}
use cardano/transaction.{
  InlineDatum, Output, OutputReference, Transaction, find_input,
}

const max_circulating_supply = 45_000_000_000_000_000

pub const staked_ada_name: AssetName = "SADA"

pub type Datum {
  owner: VerificationKeyHash,
}

pub type Redeemer {
  UpdateStakedAmount
  UpdateOwner { new_owner: VerificationKeyHash }
  RescueFunds
}

validator settings(
  protocol_boot_utxo: OutputReference,
  rescue_key: VerificationKeyHash,
) {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    when redeemer is {
      UpdateStakedAmount -> {
        expect Some(actual_datum) = datum
        expect Some(own_input) = find_input(tx.inputs, own_ref)
        expect Script(contract_hash) =
          own_input.output.address.payment_credential

        // find outputs w/ tokens
        let outputs_with_tokens =
          tx.outputs
            |> list.filter(
                fn(output) {
                  quantity_of(output.value, contract_hash, staked_ada_name) > 0
                },
              )
        // Ensure it's only one
        when outputs_with_tokens is {
          [output] ->
            // any reasons to check the amount of token is different (i.e. there was any mint or burn)
            and {
              // only token accepted in output is staked ada, no other rubbish
              policies(output.value) == [contract_hash],
              tx.extra_signatories |> list.has(actual_datum.owner),
              // ensure the only output w/ token is the contract itself
              output.address == own_input.output.address,
              output.datum == own_input.output.datum,
            }
          _ -> False
        }
      }
      UpdateOwner { new_owner } -> {
        expect Some(actual_datum) = datum
        // Find input being spent
        expect Some(own_input) = find_input(tx.inputs, own_ref)
        expect Some(output) = tx.outputs |> list.head
        and {
          // old and new owner to sign
          tx.extra_signatories |> list.has(actual_datum.owner),
          tx.extra_signatories |> list.has(new_owner),
          own_input.output.value == output.value,
          output.datum == InlineDatum(Datum(new_owner)),
        }
      }
      RescueFunds -> and {
          option.is_none(datum),
          tx.extra_signatories |> list.has(rescue_key),
        }
    }
  }

  mint(_redeemer: Data, own_policy_id: PolicyId, tx: Transaction) {
    // We need to check if it's a first mint or a following mint/burn
    let locked_inputs =
      tx.inputs
        |> list.filter(
            fn(input) {
              when input.output.address.payment_credential is {
                Script(script_hash) -> script_hash == own_policy_id
                _ -> False
              }
            },
          )

    when locked_inputs is {
      [] -> {
        // Not pre-existing utxo to spend, so this is an initial mint
        let spends_protocol_boot_utxo =
          list.any(
            tx.inputs,
            fn(input) { input.output_reference == protocol_boot_utxo },
          )
        let minted_amount =
          tx.mint |> quantity_of(own_policy_id, staked_ada_name)
        // output containing minted tokens
        expect [output] =
          list.filter(
            tx.outputs,
            fn(output) { assets.without_lovelace(output.value) == tx.mint },
          )
        // A proper datum is created
        expect InlineDatum(datum) = output.datum
        expect actual_datum: Datum = datum
        and {
          // Minting just one policy and of correct type
          policies(tx.mint) == [own_policy_id],
          minted_amount > 0,
          minted_amount < max_circulating_supply,
          // Tokens get locked in contract
          output.address.payment_credential == Script(own_policy_id),
          spends_protocol_boot_utxo,
          // Future Owner must accept the assignment (they must prove they can sign)
          tx.extra_signatories |> list.has(actual_datum.owner),
        }
      }
      [locked_input] -> {
        // calculate total
        let tokens_in_output =
          locked_input.output.value
            |> assets.merge(tx.mint)
            |> assets.without_lovelace
        let final_staked_ada_amount =
          tokens_in_output
            |> quantity_of(own_policy_id, staked_ada_name)
        // Spend checks all tokens are sent back into contract
        and {
          policies(tx.mint) == [own_policy_id],
          // no rubbish sent to output, only ada and staked_ada
          policies(tokens_in_output) == [own_policy_id],
          final_staked_ada_amount > 0,
          final_staked_ada_amount < max_circulating_supply,
        }
      }
      _ -> False
    }
  }

  else(_) {
    fail
  }
}
