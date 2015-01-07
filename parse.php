<?php
	function parse($file, $json=0){

		//intiting values
		$prog = "nope";

		//tracert
		if(strstr($file, "Traceren van") || strstr($file, "traceroute to")){
			$prog = "tracert";
			echo "selected: tracert\n";
		}

		//lft check
		if (strstr($file, "TTL  LFT trace to ")) {
			$prog = "lft";
			echo "selceted: lft\n";
		}

		switch ($prog) {
			case 'lft':
				#layer four tracer
				$ttl = lft($file);
			break;

			case 'tracert':
				#windows tracert
				$ttl = tracert($file);
			break;
			
			default:
				echo "broken\n";
				break;
		}

		//return the array or json
		if ($json == 1) {
			return json_encode($ttl);
		}else{
			return $ttl;
		}
	}

	function lft($trace){
		//initing values
		$ttl = array();

		//split the file on the line brack
		$line = explode("\n", $trace);

		foreach ($line as $node) {
			//instans for if there is no domain
			$domain = "NULL";
				//deleting empty lines
			if ($node === "") {
				continue;
			}

			//line can contain a firewall message
			//**   [firewall] the next gateway may statefully inspect packets
			if (strstr($node, "firewall")) {
				continue;
			}

			//a message about round ways
			//LFT can't seem to round-trip.  Local packet filter in the way?
			if (strstr($node, "Local packet filter in the way?")) {
				continue;
			}

			//TTL  LFT trace to {ip of target}:{port}/{protocol}
			if(strstr($node, "TTL  LFT trace to")){
				continue;
			}

			//**   [neglected] no reply packets received from TTLs 14 through 16
			if (strstr($node, "neglected")) {
			 	continue;
			}

			//**   [80/tcp failed]  Try alternate options or use -V to see packets.
			if (strstr($node, "80/tcp failed")) {
				continue;
			}

			//echo $node."\n";
				
			//split on the space
			$parts = explode(" ", $node);

			// get ttl
			if ($parts[0] === "") {
				$ttl_pos = 1;
			}else{
				$ttl_pos = 0;
			}		

			//check for a domain name.
			//and thus deteamening the possision of the ip
			$domain_pos = $ttl_pos + 3;
			if (preg_match("%[a-zA-Z]%", $parts[$domain_pos])) {
				$ip_pos = $domain_pos+1;
			}elseif($parts[$domain_pos] == "*" && $parts[$domain_pos + 1] == "[target]"){
				$ip_pos = $domain_pos+2;
			}elseif($parts[$domain_pos] == "*"){
				$ip_pos = $domain_pos+1;
			}else{
				$ip_pos = $domain_pos;
			}

			$ping_pos = $ip_pos +1;

			$data = array();

			//getting an array from the ping string.
			$ping = str_replace("ms", "", $parts[$ping_pos]);
			$ping = explode("/", $ping);
			$png = array();
			foreach ($ping as $p) {
				if ($p === "*") {
					continue;
				}
				$png[] = $p;
			}

			//cleaning ip data
			//removing the "(" and the ")" and un nessesary whith space
			$ip = trim(str_replace("(", "", str_replace(")", "", $parts[$ip_pos])));

			//getting the domain 
			if ($ip_pos == $domain_pos) {
				$domain = "NULL";
			}elseif ($parts[$domain_pos] == "*") {
				$domain = "NULL";
			}elseif ($parts[$domain_pos] == "[target]") {
				$domain = "NULL";
			}else{
				$domain = $parts[$domain_pos];
			}



			//making the data.
			$data["ip"] = $ip;

			if ($domain !== "NULL") {
				$data["domain"] = $domain;
			}

			$data["ping"] = $png;
			$ttl[$parts[$ttl_pos]] = $data;
		}
		return $ttl;
	}

	function tracert($trace){
		// initing data
		$ttl = array();
		
		//splitting on the linebrake
		//and removing the killstreak
		$line = array_map('trim',explode("\n", $trace));
		
		foreach ($line as $node) {
			//no empty line
			if ($node == "" || $node == " ") {
				continue;
			}

			//Traceren van de route naar {domainname} [ip]
			if (strstr($node, "Traceren van")) {
				continue;
			}

			//via maximaal 30 hops:
			if (strstr($node, "via maximaal")) {
				continue;
			}

			//De trace is voltooid
			if (strstr($node, "De trace is voltooid.")) {
				continue;
			}

			//Time-out bij opdracht
			if (strstr($node, "Time-out bij opdracht")) {
				continue;
			}

			//split on space
			$parts = explode(" ", $node);

			//remove unwanted parts
			$i = 0;
			foreach ($parts as $p) {
				if ($p == "" || $p == "ms") {
					unset($parts[$i]);
				}
				$i++;
			}

			//defragmenting the array
			$parts = array_values($parts);

			//the time to life is always the first part
			$tl = $parts[0];

			$png = array();

			//sometimes the ping comains a <
			$png[] = str_replace("<", "", $parts[1]);
			$png[] = str_replace("<", "", $parts[2]);
			$png[] = str_replace("<", "", $parts[3]);


			if (preg_match("%[a-zA-Z]%", $parts[4])) {
				$domain = $parts[4];
				$ip_pos = 5;
			}else{
				$ip_pos = 4;
				$domain = "NULL";
			}

			//filtering ip
			//removing the "(" and the ")" and un nessesary whith space
			$ip = trim(str_replace("[", "", str_replace("]", "", $parts[$ip_pos])));


			//making data
			$data = array();
			$data["ip"] = $ip;

			if ($domain !== "NULL") {
				$data["domain"] = $domain;
			}

			$data["ping"] = $png;

			$ttl[$tl] = $data;

			// var_dump($ttl);
	
		}
	return $ttl;
	}

?>
