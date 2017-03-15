Zaqar Demo for OpenStack Summit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


2016 Barcelona Summit Demo
==========================

How to set the test environment?

1. In this demo, the idea is based on Aodh's event alarm, so it needs to be
enabled in ceilometer, see http://docs.openstack.org/developer/aodh/event-alarm.html

The key part is add this line:

- notifier://?topic=alarm.all

to /etc/ceilometer/event_pipeline.yaml

2. We're using Zaqar's websocket and wsgi transports, so they need to be
enabled both. Luckily, it's default in devstack.

2017 Boston Summit Demo
=======================

1. Running the websocket.html under your apache server

2. Disable the CORS of your browser. And please use Firefox with cors injector addon.
See https://github.com/fredericlb/Force-CORS/releases

3. After enabled the cors injector, please use below value for its "Headers to inject" config:
 
  Access-Control-Allow-Origin *|Access-Control-Allow-Methods POST,GET|Access-Control-Expose-Headers X-Subject-Token,Vary
