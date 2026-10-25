# Deliver every status event that is waiting, now, in this process (what a queue worker does in production)
Apartment::Tenant.switch!('t8e8e68bf')
AgentEventDelivery.where(status: %w[pending retrying]).order(:id).find_each { |d| AgentEventDeliveryJob.perform_now('t8e8e68bf', d.id) }
puts AgentEventDelivery.group(:status).count.inspect
