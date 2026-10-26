# Operator actions on the issuer for the end-to-end run: suspend / reactivate the agent.
Apartment::Tenant.switch!('t8e8e68bf')
reg = AgentRegistration.find_by!(amp_address: ENV.fetch('E2E_ADDRESS'))
case ENV.fetch('E2E_ACTION')
when 'suspend' then reg.suspend!
when 'reactivate' then reg.reactivate!
end
puts "agent status: #{reg.reload.status}"
