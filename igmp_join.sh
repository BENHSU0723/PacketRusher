#!/bin/bash
socat - UDP4-DATAGRAM:0.0.0.0:6666,bind=:6666,ip-add-membership=228.216.20.30:$1,reuseaddr
