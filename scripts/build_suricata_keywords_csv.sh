#!/usr/bin/bash
# Copyright(C) 2025 Stamus Networks
#
# This file is part of Suricata Language Server.
#
# Suricata Language Server is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Suricata Language Server is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.

# -*- coding: utf-8 -*-
SURICATA_DIR=${1:-/opt/git/suricata}
OUTPUT_DIR=${2:-/tmp/}
FILE_PREFIX=${3:-suricata-keywords}

cd ${SURICATA_DIR}

if [ ! -d ${OUTPUT_DIR} ]; then
    mkdir -p ${OUTPUT_DIR}
fi

TAGS_LIST=$(git tag | grep "^suricata-" | sed 's/suricata-//' | grep -vi beta | grep -vi rc | sort -)

cd -

for TAG in ${TAGS_LIST}; do
    echo "Building Suricata ${TAG} keywords CSV"
    docker pull jasonish/suricata:${TAG} && docker run --rm -ti jasonish/suricata:${TAG} --list-keywords=csv| grep -A1000 "^name">${OUTPUT_DIR}/${FILE_PREFIX}-v${TAG}.csv
    docker rmi jasonish/suricata:${TAG}
done
