Zaqar Demo for OpenStack Barcelona Summit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

How to set the test environment?

1. In this demo, the idea is based on Aodh's event alarm, so it needs to be
enabled in ceilometer, see http://docs.openstack.org/developer/aodh/event-alarm.html

The key part is add this line:

- notifier://?topic=alarm.all

to /etc/ceilometer/event_pipeline.yaml

2. We're using Zaqar's websocket and wsgi transports, so they need to be
enabled both. Luckily, it's default in devstack.