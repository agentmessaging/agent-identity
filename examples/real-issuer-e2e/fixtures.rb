# Run in the issuer's test environment on a dedicated database. Creates the pieces a real flow needs:
# a company with an OIDC issuer URL, a role, a sponsor, the agent registration for the REAL client's key,
# and a connected app (AgentResource) for the old system.
require 'json'
home = ENV.fetch('E2E_HOME')
cfg  = JSON.parse(File.read("#{home}/.agent-messaging/agents/#{ENV.fetch('E2E_AGENT')}/config.json"))['agent']
pub  = File.read("#{home}/.agent-messaging/agents/#{ENV.fetch('E2E_AGENT')}/keys/public.pem")

company = Company.find_by!(schema_name: 't8e8e68bf')
company.update!(oidc_enabled: true, oidc_issuer_url: ENV.fetch('E2E_ISSUER'))
company.send(:generate_rsa_keys) unless company.has_valid_rsa_keys?
company.reload
Apartment::Tenant.switch!(company.schema_name)

scopes = %w[contacts:read contacts:create orders:delete reports:read]
role = Role.find_or_create_by!(name: 'e2e_agent') do |r|
  r.unique_id = SecureRandom.uuid; r.status = 'active'; r.enabled = 'enabled'; r.privilege_level = 5; r.protected = false
end
role.permissions = scopes.map { |s| Permission.find_or_create_by!(name: s, status: 'active') { |p| p.unique_id = SecureRandom.uuid; p.enabled = true } }

sponsor = User.create!(email: "ana_#{SecureRandom.hex(3)}@acme.example", uid: "ana_#{SecureRandom.hex(3)}@acme.example", username: "ana#{SecureRandom.hex(3)}",
                       name: 'Ana Sponsor', password: 'password', provider: 'email', confirmed_at: DateTime.now, unique_id: SecureRandom.uuid, role: role)

reg = AgentRegistration.create!(
  name: cfg['name'], amp_address: cfg['address'], amp_fingerprint: cfg['fingerprint'], amp_public_key: pub,
  key_algorithm: 'Ed25519', role: role, unique_id: SecureRandom.uuid, status: 'active', enabled: true,
  token_lifetime: 900, registered_by_user_id: sponsor.id
)
res = AgentResource.create!(identifier: ENV.fetch('E2E_RESOURCE'), name: 'Acme CRM (old system)', receiver_url: ENV['E2E_RECEIVER'],
                            scope_ceiling: %w[contacts:read contacts:create orders:delete reports:read])

puts JSON.generate(issuer: company.oidc_issuer, url_id: company.url_id, agent_address: reg.amp_address, agent_id: reg.unique_id,
                   resource: res.identifier, client_id: res.client_id, client_secret: res.client_secret)
