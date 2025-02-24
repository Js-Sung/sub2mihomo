#!/bin/bash

SUBLINK='
https://node.freeclashnode.com/uploads/2025/02/0-20250222.yaml
https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt
https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt
https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2
https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/airport_sub_merge.txt
##https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt
#https://yourclashsublink.com/xxx?yyy=1
#https://othersublink.com/zzz?aaa=2
#vmess://xxxyyyzzz
#ssr://balabalabala
'

TEMPLATE="ts.yaml"
CFGFILE="/tmp/clash.yaml"
CFGDIR="miho_cfg"
BIN="mihomo"
LOCKFILE="/tmp/clash.lock"

UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'

# error msg
log_e(){ echo -e "\x1b[30;41merror:\x1b[0m \x1b[31m${*}\x1b[0m" >&2; }
# info msg
log_i(){ echo -e "\x1b[30;42minfo:\x1b[0m \x1b[32m${*}\x1b[0m" >&2; }
# warn msg
log_w(){ echo -e "\x1b[30;43mwarning:\x1b[0m \x1b[33m${*}\x1b[0m" >&2; }

url_decode() {
	echo -e $(echo "$@" | sed -E 's/%([a-fA-F0-9]{2})/\\x\1/g')
}

decode_base64() {
	local a
	case "$((${#1} % 4))" in
		2) echo "$1==" ;;
		3) echo "$1=" ;;
		*) echo "$1" ;;
	esac | sed 'y/-_/+\//' | grep -o "^[a-zA-Z0-9+/=]*" | base64 -d 2>/dev/null
}

decode_ss() {
	local password cipher server port name t ss_ciphers
	ss_ciphers="@rc4-md5@aes-128-gcm@aes-192-gcm@aes-256-gcm@aes-128-cfb@aes-192-cfb@aes-256-cfb@aes-128-ctr@aes-192-ctr@aes-256-ctr@camellia-128-cfb@camellia-192-cfb@camellia-256-cfb@bf-cfb@chacha20-ietf-poly1305@xchacha20-ietf-poly1305@salsa20@chacha20@chacha20-ietf@2022-blake3-aes-128-gcm@2022-blake3-aes-256-gcm@2022-blake3-chacha20-poly1305@2022-blake3-chacha12-poly1305@2022-blake3-chacha8-poly1305@"
	if echo "$1" | grep -qP '^[-_a-zA-Z0-9+/=]+$' 
	then
		port=$(echo "$1" | base64 -d)
		cipher=$(echo "$port" | awk -F'[@:]' '{print $1}')
		password=$(echo "$port" | awk -F'[@:]' '{print $2}')
		server=$(echo "$port" | awk -F'[@:]' '{print $3}')
		port=$(echo "$port" | awk -F'[@:]' '{print $4}')
	elif echo "$1" | grep -qP '@\S+:\d+' 
	then
		password=$(decode_base64 $(echo "$1" | awk -F'[@:]' '{print $1}'))
		cipher=$(echo "$password" | awk -F'[:]' '{print $1}')
		password=$(echo "$password" | awk -F'[:]' '{print $2}')
		server=$(echo "$1" | awk -F'[@:]' '{print $2}')
		port=$(echo "$1" | awk -F'[@:#?/]' '{print $3}')
		name=$(url_decode $(echo "$1" | grep -oP '(?<=#)\S+'))
	else
		name=$(url_decode $(echo "$1" | grep -oP '(?<=#)\S+'))
		port=$(decode_base64 $(echo "$1" | sed -E 's/#.*//g'))
		cipher=$(echo "$port" | awk -F'[@:]' '{print $1}')
		password=$(echo "$port" | awk -F'[@:]' '{print $2}')
		server=$(echo "$port" | awk -F'[@:]' '{print $3}')
		port=$(echo "$port" | awk -F'[@:]' '{print $4}')
	fi
	[ -z "$port" -o -z "$cipher" -o -z "$(echo "$ss_ciphers" | grep -iP "@$cipher@")" ] && return 1
	t="{\"name\": \"${name:-ss-$(head -20 /dev/urandom | md5sum | cut -c '1-10')}\", \"server\": \"$server\", \"port\": $port, \"password\": \"$password\", \"cipher\": \"$cipher\", \"type\": \"ss\"}"
	echo "$t"
}

decode_ssr() {
	local a server port protocol cipher obfs password obfsparam protoparam remarks group
	echo "$1" | grep -qP '[^-_a-zA-Z0-9+/=]' && return 1
	a=$(decode_base64 "$1")
	IFS=:\  read -r server port protocol cipher obfs password <<- EOF
		${a%%/?*}
	EOF
	while IFS='=' read -r key value; do
		[ -n "$value" ] && eval "$key=\"$(decode_base64 "$value")\""
	done <<- EOF
		$(echo "${a#*/?}" | sed 'y/&/\n/')
	EOF
	remarks=$(echo "$remarks" | grep -ax '.*')
	t="{\"name\":\"${remarks:-ssr-$(head -20 /dev/urandom | md5sum | cut -c '1-10')}\", \"server\": \"$server\", \"port\": $port, \"password\": \"$(decode_base64 "$password")\", \"cipher\": \"$cipher\", \"protocol\": \"$protocol\", \"protocol_param\": \"${protoparam}\", \"obfs\": \"$obfs\", \"obfs_param\": \"${obfsparam}\", \"type\": \"ssr\"}"
	echo "$t"
}

decode_vmess() {
	local a
	if ! echo "$1" | grep -qP '[^-_a-zA-Z0-9+/=\r]'
	then
		a=$(decode_base64 "$1")
		if a=$(echo "$a" | jq -c --argjson defaults "{\"udp\":true,\"xudp\":true,\"tls\":false,\"skip-cert-verify\":false,\"cipher\":\"auto\",\"ps\":\"vmess-$(head -20 /dev/urandom|md5sum|cut -c '1-10')\"}" '(if .v and (.v|tonumber)==1 then (.host|split(";")|.[0]) else .host end) as $host|(if .v and (.v|tonumber)==1 then (.host|split(";")|.[1]) else .path end) as $path|.alpn as $alpn|.sni as $sni|{name:(.ps//($defaults|.ps)),server:(.add//error),port:(.port|tonumber//error),type:"vmess",uuid:(.id//error),alterId:(.aid // 0)|tonumber,cipher:(if .scy and (.scy != "") then .scy else ($defaults|.cipher) end),udp:(.udp//($defaults|.udp)),xudp:(.xudp//($defaults|.xudp)),tls:(if .tls and ((.tls==true)or(.tls|test("tls$"))) then true else ($defaults|.tls) end),"skip-cert-verify":($defaults|."skip-cert-verify"),network:(if .type=="http" then .type elif (.net|ascii_downcase|test("http$")) then "h2" else (.net|ascii_downcase) end)}|if ($sni and $sni!="") then .+{servername:$sni} else . end|.network as $n|if (.tls and (.tls==true)) and ($alpn|length>0) then .+{alpn:[$alpn|splits(",\\s*";"")]} else . end|if $n=="grpc" then .+{"grpc-opts":{"grpc-service-name":($path//"")}} elif $n=="http" then .+{($n+"-opts"):{path:[($path//"/")],headers:(if $host and $host!="" then{Host:(if ($host|type)=="array" then ($host) else [($host)] end)}else{Host:[.server]}end)}} elif $n=="ws" or "$n"=="h2" then .+{($n+"-opts"):{path:($path//(if $n=="ws" then "/" else "" end)),headers:(if $host and $host!="" then{Host:($host)}else{Host:.server}end)}} else . end')
		then
			echo "$a"
		fi
	else
		echo "不支持" >&2
	fi
}

# tfo未处理
decode_trojan() {
	local t svrname v scv type sni secure path name port server password fp alpn
	password=$(url_decode $(echo "$1" | awk -F'[@:?]' '{print $1}'))
	server=$(echo "$1" | awk -F'[@:?]' '{print $2}')
	port=$(echo "$1" | awk -F'[@:?#&]' '{print $3}')
	name=$(url_decode "$(echo "$1" | grep -oP '(?<=#)\S+')")
	sni=$(echo "$1" | grep -oP '(?:peer|sni)=\K[^\s#&]+' | sed 'q')
	fp=$(echo "$1" | grep -oP '(?<=fp=)[^\s#&]+')
	type=$(echo "$1" | grep -oP '(?<=type=)[^\s#&]+')
	path=$(url_decode $(echo "$1" | grep -oP '(?<=path=)[^\s#&]+'))
	secure=$(echo "$1" | grep -oP '(?<=allowInsecure=)[^\s#&]+')
	alpn=$(url_decode $(echo "$1" | grep -oP '(?<=alpn=)[^\s#&]+'))
	[[ -n "$fp" ]] && v=${v}", \"client-fingerprint\": \"$fp\""
	[[ -n "$alpn" ]] && v=${v}", \"alpn\": "$(echo "\"$alpn\"" | jq -c '.|split(",\\s*";"")')
	[[ -n "$secure" ]] && { [[ "$secure" == 0 ]] && scv=false || scv=true ; }
	[[ -n "$sni" ]] && v=${v}", \"sni\": \"$sni\""
	[[ -n "$scv" ]] && v=${v}", \"skip-cert-verify\": $scv"
	if [[ -n "$type" ]]
	then
		v=${v}", \"network\": \"$type\""
		if [[ "$type" == "ws" ]]
		then
			v=${v}", \"ws-opts\": {\"path\": \"$path\", \"headers\": {\"User-Agent\": \"${UA}\"}}"
		elif [[ "$type" == "grpc" ]]
		then
			svrname=$(echo "$1" | grep -oP '(?<=serviceName=)[^\s#&]+')
			v=${v}", \"grpc-opts\": {\"serviceName\": \"$svrname\"}"
		fi
	fi
	t="{\"name\":\"${name:-$server:$port}\", \"server\": \"$server\", \"port\": $port, \"type\": \"trojan\", \"password\": \"$password\"${v}}"
	echo "$t"
}

# udp true
decode_vless() {
	local t v v3 v2 svrname network faketype switch sid pubk sni secure path host name port server uuid fp alpn
	uuid=$(echo "$1" | awk -F'[@:?]' '{print $1}')
	server=$(echo "$1" | awk -F'[@:?]' '{print $2}')
	port=$(echo "$1" | awk -F'[@:?/#&]' '{print $3}')
	name=$(url_decode "$(echo "$1" | grep -oP '(?<=#)\S+')")
	secure=$(echo "$1" | grep -oP '(?<=security=)[^\s#&]+')
	if echo "$secure" | grep -iPq 'tls|reality'
	then
		v=${v}", \"tls\": true"
		fp=$(echo "$1" | grep -oP '(?<=fp=)[^\s#&]+')
		v=${v}", \"client-fingerprint\": \"${fp:-chrome}\""
		alpn=$(url_decode $(echo "$1" | grep -oP '(?<=alpn=)[^\s#&]+'))
		[[ -n "$alpn" ]] && v=${v}", \"alpn\": "$(echo "\"$alpn\"" | jq -c '.|split(",\\s*";"")')
	fi
	sni=$(echo "$1" | grep -oP '(?<=sni=)[^\s#&]+')
	[[ -n "$sni" ]] && v=${v}", \"servername\": \"$sni\""
	pubk=$(echo "$1" | grep -oP '(?<=pbk=)[^\s#&]+')
	if [[ -n "$pubk" ]]
	then
		sid=$(echo "$1" | grep -oP '(?<=sid=)[^\s#&]+')
		v=${v}", \"reality-opts\": {\"public-key\": \"$pubk\", \"short-id\": \"$sid\"}"
	fi
	switch=$(echo "$1" | grep -oP '(?<=packetEncoding=)[^\s#&]+')
	if [[ "$switch" == "packet" ]]
	then
		v=${v}", \"packet-addr\": true"
	elif ! [ -z "$switch" -o "$switch" = "none" ]
	then
		v=${v}", \"xudp\": true"
	fi
	network=$(echo "$1" | grep -oP '(?<=type=)[^\s#&]+' | sed -E 's/(.*)/\L\1/;q')
	[[ -z "$network" ]] && network='tcp'
	faketype=$(echo "$1" | grep -oP '(?<=headerType=)[^\s#&]+' | sed -E 's/(.*)/\L\1/;q')
	if [[ "$faketype" = "http" ]]
	then
		network='http'
	elif [[ "$network" == "http" ]]
	then
		network='h2'
	fi
	v=${v}", \"network\": \"$network\""
	host=$(url_decode $(echo "$1" | grep -oP '(?<=host=)[^\s#&]+'))
	[[ -n "$host" ]] && v2="\"Host\": \"$host\""
	path=$(url_decode $(echo "$1" | grep -oP '(?<=path=)[^\s#&]+'))
	v3=", \"path\": \"${path:-/}\""
	if [[ "$network" = "tcp" ]]
	then
		if ! [ -z "$faketype" -o "$faketype" = "none" ]
		then
			method=$(echo "$1" | grep -oP '(?<=method=)[^\s#&]+')
			[[ -n "$method" ]] && v3=${v3}", \"method\": \"$method\""
			v=${v}", \"http-opts\": {\"headers\": {$v2}$v3}"
		fi
	elif [[ "$network" = "http" ]]
	then
		v=${v}", \"h2-opts\": {\"headers\": {$v2}$v3}"
	elif [[ "$network" = "ws" ]]
	then
		v=${v}", \"ws-opts\": {\"headers\": {${v2:+$v2, }\"User-Agent\": \"$UA\"}$v3}"
	elif [[ "$network" = "grpc" ]]
	then
		svrname=$(echo "$1" | grep -oP '(?<=serviceName=)[^\s#&]+')
		v=${v}", \"grpc-opts\": {\"grpc-service-name\": \"$svrname\"}"
	fi
	t="{\"name\":\"${name:-$server:$port}\", \"server\": \"$server\", \"port\": $port, \"type\": \"vless\", \"uuid\": \"$uuid\", \"udp\": true${v}}"
	echo "$t"
}

decode_hysteria() {
	local t v sni insecure name port server obfs up down alpn protocol auth
	server=$(echo "$1" | awk -F'[:?]' '{print $1}')
	port=$(echo "$1" | awk -F'[:?]' '{print $2}')
	name=$(url_decode "$(echo "$1" | grep -oP '(?<=#)\S+')")
	sni=$(echo "$1" | grep -oP '(?<=peer=)[^\s#&]+')
	obfs=$(echo "$1" | grep -oP '(?<=obfs=)[^\s#&]+')
	alpn=$(url_decode $(echo "$1" | grep -oP '(?<=alpn=)[^\s#&]+'))
	[[ -n "$alpn" ]] && v=${v}", \"alpn\": "$(echo "\"$alpn\"" | jq -c '.|split(",\\s*";"")')
	auth=$(echo "$1" | grep -oP '(?<=auth=)[^\s#&]+')
	protocol=$(echo "$1" | grep -oP '(?<=protocol=)[^\s#&]+')
	up=$(echo "$1" | grep -oP '(?:up(mbps)?=)\K[^\s#&]+' | sed 'q')
	[[ -n "$up" ]] && v=${v}", \"up\": \"$up\""
	down=$(echo "$1" | grep -oP '(?:down(mbps)?=)\K[^\s#&]+' | sed 'q')
	[[ -n "$down" ]] && v=${v}", \"down\": \"$down\""
	insecure=$(echo "$1" | grep -oP '(?<=insecure=)[^\s#&]+')
	echo "$insecure" | grep -iPq 'y|t|1|on' && insecure=true || insecure=false
	t="{\"name\":\"${name:-$server:$port}\", \"server\": \"$server\", \"port\": $port, \"type\": \"hysteria\", \"sni\": \"$sni\", \"obfs\": \"$obfs\", \"auth_str\": \"$auth\", \"protocol\": \"$protocol\", \"skip-cert-verify\": $insecure${v}}"
	echo "$t"
}

decode_hysteria2() {
	local t v sni insecure name port server obfs up down alpn password
	password=$(echo "$1" | grep -oP '^[^\?]+')
	server=$(echo "$password" | grep -oP '^(\S+@)?\K[^\s#&:@]+')
	port=$(echo "$1" | grep -oP '(?<=:)\d+')
	[[ -z "$port" ]] && port=443
	password=$(echo "$password" | grep -oP '^[^\s#&:@]+(?=@)')
	[[ -n "$password" ]] && v=${v}", \"password\": \"$password\""
	name=$(url_decode "$(echo "$1" | grep -oP '(?<=#)\S+')")
	obfs=$(echo "$1" | grep -oP '(?<=obfs=)[^\s#&]+')
	if [[ -n "$obfs" ]] && ! echo "$obfs" | grep -iPq 'none' 
	then
		obps=$(echo "$1" | grep -oP '(?<=obfs-password=)[^\s#&]+')
		v=${v}", \"obfs\": \"$obfs\", \"obfs-password\": \"$obps\""
	fi
	sni=$(echo "$1" | grep -oP '(?:peer|sni)=\K[^\s#&]+' | sed 'q')
	[[ -n "$sni" ]] && v=${v}", \"sni\": \"$sni\""
	insecure=$(echo "$1" | grep -oP '(?<=insecure=)[^\s#&]+')
	echo "$insecure" | grep -iPq 'y|t|1|on' && insecure=true || insecure=false
	alpn=$(url_decode $(echo "$1" | grep -oP '(?<=alpn=)[^\s#&]+'))
	[[ -n "$alpn" ]] && v=${v}", \"alpn\": "$(echo "\"$alpn\"" | jq -c '.|split(",\\s*";"")')
	fp=$(echo "$1" | grep -oP '(?<=pinSHA256=)[^\s#&]+')
	[[ -n "$fp" ]] && v=${v}", \"fingerprint\": \"$fp\""
	up=$(echo "$1" | grep -oP '(?:up(mbps)?=)\K[^\s#&]+' | sed 'q')
	[[ -n "$up" ]] && v=${v}", \"up\": \"$up\""
	down=$(echo "$1" | grep -oP '(?:down(mbps)?=)\K[^\s#&]+' | sed 'q')
	[[ -n "$down" ]] && v=${v}", \"down\": \"$down\""
	t="{\"name\":\"${name:-$server:$port}\", \"server\": \"$server\", \"port\": $port, \"type\": \"hysteria2\", \"skip-cert-verify\": $insecure${v}}"
	echo "$t"
}

decode_link() {
	local a i
	
	[[ "$#" == 0 ]] && return 1
	echo "$*" | grep -qP '\S+' || return 1
	
	if a=$(echo "$*" | yq -e -py -oj -I0 '.proxies[]' 2>/dev/null)
	then
		echo -n "-" >&2
		echo "$a"
	elif ! echo "$*" | grep -Pq '[^-_a-zA-Z0-9+/=\r]'
	then
		if a=$(decode_base64 "$*" | grep -P '^(?:[\x00-\x7F]+|[\xC0-\xDF][\x80-\xBF]+|[\xE0-\xEF][\x80-\xBF]{2}+|[\xF0-\xF7][\x80-\xBF]{3}+)$')
		then
			decode_link "$a"
		else
			return 1
		fi
	else
		for i in $@
		do
			echo -n "-" >&2
			case "${i%%:*}" in
				ss)
					decode_ss "${i#*://}" & ;;
				ssr)
					decode_ssr "${i#*://}" & ;;
				vmess)
					decode_vmess "${i#*://}" & ;;
				trojan)
					decode_trojan "${i#*://}" & ;;
				vless)
					decode_vless "${i#*://}" & ;;
				http|https)
					decode_link "$(curl -L --retry-all-errors --retry 3 -s "$i")" & ;;
				hysteria)
					decode_hysteria "${i#*://}" & ;;
				hysteria2|hy2)
					decode_hysteria2 "${i#*://}" & ;;
				*)
					continue ;;
			esac
		done
		wait
	fi
	return 0
}

genNodes(){
	local a ts te
	[ -z "$*" ] && { log_e "no links to decode."; return 1; }
	log_i 'start downloading nodes.'
	ts=$(date +%s)
	a=$(decode_link "$*")
	te=$(date +%s)
	echo '' >&2
	log_i "消耗$((te-ts))s"
	echo "$a"
	return 0
}

genCFGfile(){
	local a b c
	[[ ! -f "$TEMPLATE" ]] && { log_e "no template yaml file."; return 1; }
	a=$(echo "$*" | grep -ax '.*')	# only utf-8 chars
	[ "$(echo "$a" | sed -E '/^\s*$/d' | wc -l)" -lt 1 ] && { log_e "no nodes."; return 2; }
	b=$(echo "$a" | yq -pj -oy ea '. as $a ireduce([]; . + $a) | unique_by(.name)')
	c=$(echo "$b" | grep -P '^-' | sed '/^\s*$/d' | wc -l)
	log_i "found $c nodes."
	[ "$c" = "0" ] && return 3
	rm -f "$CFGFILE"
	echo "$b" | yq -oy ea '. as $nodes|load("'"$TEMPLATE"'") as $final|$final|with(.; .proxies += $nodes, (.proxy-groups[]|select(.name|test("广告|拦截|直连|净化")|not)|.proxies) += [$nodes.[].name])' >"$CFGFILE"
	log_w "config file generated."
	return 0
}

restartClash()
{
	# 杀死clash进程
	killall "${BIN##*/}" &> /dev/null
	sleep 1
	if ! killall -0 "${BIN##*/}" &> /dev/null
	then
		log_i "kill $BIN successfully."
	else
		log_e "failed to kill $BIN."
		return 1
	fi

	# 启动clash
	nohup $BIN -f "$CFGFILE" -d "$CFGDIR" &> /dev/null &
	log_i "waiting for $BIN up."
	sleep 2

	if killall -0 "${BIN##*/}" &> /dev/null
	then
		log_i "$BIN started successfully."
	else
		log_e "failed to start $BIN."
		return 2
	fi
	return 0
}

#####################################
# 进入脚本所在目录
cd $(dirname "$0")

{
	flock -n 198
	[ "$?" != "0" ] && { log_e "failed to get lock file. Is '$0' runing already?"; exit 40; }
	
	nodes=$(genNodes "$SUBLINK")
	ret=$?
	if [ "$ret" != "0" ]
	then 
		log_e "failed to decode sublinks with error code $ret."
		flock -u 198
		rm -f "$LOCKFILE"
		exit 1
	fi
	
	genCFGfile "$nodes"
	ret=$?
	if [ "$ret" != "0" ]
	then 
		log_e "failed to generate cfg file with error code $ret."
		flock -u 198
		rm -f "$LOCKFILE"
		exit 2
	fi
	
	restartClash
	ret=$?
	if [ "$ret" != "0" ]
	then
		log_e "failed to start $BIN with error code $ret."
		flock -u 198
		rm -f "$LOCKFILE"
		exit 3
	fi
	
	flock -u 198
	log_i "all jobs done."
} 198<>"$LOCKFILE"

rm -f "$LOCKFILE"

exit 0
