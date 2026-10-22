# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.StoreError do
  @moduledoc false
  # Tells a store that said "no" from a store that did not answer.
  #
  # Every lookup on the request path (the user behind a bearer token, the
  # client behind a `client_id`, a refresh token) must treat the two
  # differently: a record that is missing, forbidden or asked for by a
  # malformed key is the caller's problem and gets the protocol's refusal
  # (`invalid_token`, `invalid_client`, `invalid_grant`), after which clients
  # discard their credentials. A data layer that failed (`Unavailable` from
  # ash_postgres, a connection error, anything unknown) is the server's
  # problem and must be reported as such, so the credentials survive the
  # outage.

  @refusals [
    Ash.Error.Query.NotFound,
    Ash.Error.Invalid.InvalidPrimaryKey,
    Ash.Error.Query.InvalidArgument,
    Ash.Error.Query.InvalidFilterValue
  ]

  @doc "Whether the store answered and the answer was no."
  @spec refusal?(term()) :: boolean()
  def refusal?(%{errors: [_ | _] = errors}), do: Enum.all?(errors, &refusal?/1)
  def refusal?(%struct{}), do: struct in @refusals or forbidden?(struct)
  def refusal?(_), do: false

  # `Ash.Error.Forbidden` and every error under it (a policy, a forbidden
  # field) are answers, not failures.
  defp forbidden?(struct),
    do: struct |> Atom.to_string() |> String.starts_with?("Elixir.Ash.Error.Forbidden")
end
