#!/bin/bash
CONTROLLER_IP=localhost
CONTROLLER_REST_PORT=8081


curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/whitelist/add/json -X POST -d '{"server-ip-address":"10.0.0.211", "server-tcp-port":"5001", "client-ip-address":"10.0.0.111"}' | python -m json.tool


curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/agent/add/json -X POST -d '{"ip-address":"10.0.0.12", "control-port":"9998", "data-port":"9877", "feedback-port":"9997", "stats-port":"9999"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/agent/add/json -X POST -d '{"ip-address":"10.0.0.22", "control-port":"9998", "data-port":"9877", "feedback-port":"9997", "stats-port":"9999"}' | python -m json.tool




curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"parallel-connections":"3"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"queue-capacity":"3"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"buffer-size":"20000"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"idle-timeout":"2000"}' | python -m json.tool

exit 0
