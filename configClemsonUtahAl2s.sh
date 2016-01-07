#!/bin/bash
CONTROLLER_IP=localhost
CONTROLLER_REST_PORT=8080

curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/agent/add/json -X POST -d '{"ip-address":"10.0.0.1", "control-port":"9998", "data-port":"9877", "feedback-port":"9998", "stats-port":"9999"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/agent/add/json -X POST -d '{"ip-address":"10.0.0.3", "control-port":"9998", "data-port":"9877", "feedback-port":"9998", "stats-port":"9999"}' | python -m json.tool

curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/whitelist/add/json -X POST -d '{"server-ip-address":"10.0.0.4", "server-tcp-port":"5001", "client-ip-address":"10.0.0.2"}' | python -m json.tool

curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"parallel-connections":"32"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"queue-capacity":"5"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"buffer-size":"60000"}' | python -m json.tool
curl http://$CONTROLLER_IP:$CONTROLLER_REST_PORT/wm/sos/config/json -X POST -d '{"idle-timeout":"10"}' | python -m json.tool

exit 0
