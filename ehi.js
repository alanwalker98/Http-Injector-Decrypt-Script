const fs = require("fs")
const colors = require("colors")

String.prototype.fromBase64 = function(charsetString, paddingString) {
    if (!charsetString) {
    	charsetString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    }
    
    if (!paddingString) {
    	paddingString = "=";
    }
    
    const base64chars = charsetString;
    let result = '', encoded = '';
    
    const base64inv = {};
    
    for (let i = 0; i < base64chars.length; i++)
      base64inv[base64chars[i]] = i;
  
    const base64regex = new RegExp(`[^${base64chars}=]`, 'g');
    encoded = this.replace(base64regex, '');
  
    const onePadding = encoded.charAt(encoded.length - 1) === paddingString;
    const twoPadding = encoded.charAt(encoded.length - 2) === paddingString;  
    const padding = onePadding ? twoPadding ? 'AA' : 'A' : '';
    encoded = encoded.substring(0, encoded.length - padding.length) + padding;
  
    for (let i = 0; i < encoded.length; i += 4) {
    	const dn = base64inv[encoded.charAt(i)];
        const en = base64inv[encoded.charAt(i + 1)];
        const fn = base64inv[encoded.charAt(i + 2)];
        const gn = base64inv[encoded.charAt(i + 3)];
        const d = dn << 18;
        const e = en << 12;
        const f = fn << 6;
        const g = gn;
        const n = d + e + f + g;        
        const a = (n >>> 16) & 255;
        const b = (n >>> 8) & 255;
        const c = n & 255;     
        result += String.fromCharCode(a, b, c);
    }
    return result.substring(0, result.length - padding.length);
}

function reverseString(string) {
    let newString = "";
    let stringLength = string.length - 1;
    while(stringLength != -1) {
        newString += string[stringLength];
        stringLength--;
    }
    return newString;
}

function xorCrypto(key, data) {
    let preData, result;
    preData = "";
    result = "";
    for (let c = 0; c < data.length;) {
        if (c >= data.length) {
        	break;
        }
        preData += String.fromCharCode(parseInt(data.substring(c, c + 2), 16));
        c = c + 2;
    }
    for (let a = 0, b = 0; a < preData.length; a++, b++) {
        if (b >= key.length) {
        	b = 0
        }
        result += String.fromCharCode(preData.charCodeAt(a) ^ key.charCodeAt(b));
    }
    return result;
}

const decryptEhi = (configSalt, value) => {
	const text = reverseString(value).fromBase64("RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs?", "?")
	return xorCrypto(configSalt, text)
}

const decryptEhil = (configSalt, value) => {
	const text = reverseString(value).fromBase64("t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN?", "?")
	return xorCrypto(configSalt, text)
}

class HttpInjector {
	constructor(ehi) {
		this.ehi = ehi
		this.salt = ehi.configSalt
		this.tunnelMode = ehi.tunnelType
	}
	decrypt(key) {
		if (this.ehi.configVersionCode > 10000) {
			return (this.ehi[key]) ? decryptEhil(this.salt, this.ehi[key]) : 'N/A'
		} else {
			return (this.ehi[key]) ? decryptEhi(this.salt, this.ehi[key]) : 'N/A'
		}
	}
	tunnelType() {
		switch (this.tunnelMode) {
			case "ssl_proxy_payload_ssh":
			    return "SSH -> TLS/SSL + Proxy -> Custom Payload"
			case "http_obfs_shadowsocks":
			    return "Shadowsocks -> HTTP (Obfs)"
			case "ssl_ssh":
			    return "SSH -> TLS/SSL (stunnel)"
			case "proxy_payload_ssh":
			    return "SSH -> HTTP Proxy -> Custom Payload"
			case "proxy_ssh":
			    return "SSH -> HTTP Proxy"
			case "direct_payload_ssh":
			    return "SSH -> Direct -> Custom Payload"
			default:
			    return this.tunnelMode
		}
	}
}

const parseConfig = (ehi, personalizado = true) => {
	
	if (!ehi.configSalt) ehi.configSalt = "EVZJNI"
	
	const httpInjector = new HttpInjector(ehi)
	
	var message = ""

	if (personalizado) {
		
		if (ehi.tunnelType == "http_obfs_shadowsocks") {
			
			const settings = JSON.parse(httpInjector.decrypt("httpObfsSettings"))
			
			message += `Shadowsocks:\n`
			message += `Host: ${httpInjector.decrypt("shadowsocksHost")}\n`
			message += `Port:a ${ehi.shadowsocksPort}\n`
			message += `Senha: ${httpInjector.decrypt("shadowsocksPassword")}\n`
			message += `EncryptMethod: ${ehi.shadowsocksEncryptionMethod.toUpperCase()}\n\n`
			message += `Settings:\n`
			message += `Method: ${settings.httpMethod}\n`
			message += `Hostname: ${settings.hostname}\n\n`
			
			message += `tunnel type: ${httpInjector.tunnelType()}\n\n`
			
		} else if (ehi.tunnelType == "direct_v2r_vmess") {
			
			message += `V2Ray Settings:\n`
			message += `Protocol: ${httpInjector.decrypt("v2rProtocol")}\n`
			message += `Host: ${httpInjector.decrypt("v2rHost")}\n`
			message += `Porta: ${httpInjector.decrypt("v2rPort")}\n`
			message += `User ID: ${httpInjector.decrypt("v2rUserId")}\n`
			message += `Alter ID: ${httpInjector.decrypt("v2rAlterId")}\n`
			message += `Security: ${httpInjector.decrypt("v2rVlessSecurity")}\n`
			
			if (ehi.v2rNetwork) message += `Network Type: ${httpInjector.decrypt("v2rNetwork")}\n`
			if (ehi.v2rWsHeader) message += `Header: ${httpInjector.decrypt("v2rWsHeader")}\n`
			if (ehi.v2rWsPath) message += `Header Path: ${httpInjector.decrypt("v2rWsPath")}\n`
			if (ehi.v2rTlsSni) message += `TLS SNI: ${httpInjector.decrypt("v2rTlsSni")}\n`
			
			if (ehi.v2rRawJson) {
				message = httpInjector.decrypt("v2rRawJson")
			}
			
		} else if (["ssl_proxy_payload_ssh","ssl_ssh","proxy_payload_ssh","direct_payload_ssh","proxy_ssh"].includes(ehi.tunnelType)) {
			
			message += `SSH:\n`
			
			if (ehi.overwriteServerData) {
				var serverData = JSON.parse(ehi.overwriteServerData)
				message += `Servidor da Evozi: ${serverData.name} (${serverData.ip})\n`
				message += `Ports: ${serverData.sshPort} SSH, ${serverData.sshSslPort} SSL\n\n`
				// message += `User: ${serverData.sshUsername}\n`
				// message += `Password: ${serverData.sshPassword}\n\n`
			} else {
				message += `Host: ${httpInjector.decrypt("host")}\n`
				message += `Port: ${ehi.port}\n`
				message += `User: ${httpInjector.decrypt("user")}\n`
				message += `pass: ${httpInjector.decrypt("password")}\n\n`
			}
			
			if (ehi.configHwid) {
				message += `HWID: ${ehi.configHwid}\n`
			}
			
			if (ehi.payload) {
				message += `Payload: ${httpInjector.decrypt("payload")}\n\n`
			}
			
			if (ehi.remoteProxy) {
				if (ehi.remoteProxyUsername) {
					message += `Proxy: ${httpInjector.decrypt("remoteProxy")}\n`
					message += `Proxy Auth: ${httpInjector.decrypt("remoteProxyUsername")} : ${httpInjector.decrypt("remoteProxyPassword")}\n`
				} else {
					message += `Proxy: ${httpInjector.decrypt("remoteProxy")}\n\n`
				}
				
			} else if (ehi.overwriteServerData) {
				message += `Proxy: ${serverData.proxyIp}\n`
				message += `ProxyPort: ${serverData.proxyPort}\n\n`
			}
			
			if (ehi.sniHostname != "N/A" && ehi.tunnelType != "proxy_payload_ssh") {
				message += `SNI: ${httpInjector.decrypt("sniHostname")}\n\n`
			}
			
			message += `tunnel type: ${httpInjector.tunnelType()}\n\n`
			
		}
		
		//delete ehi.configSalt
		delete ehi.configMessage
		
		console.log(message)
		
		fs.writeFileSync("/sdcard/ehi.txt", message)
		fs.writeFileSync("/sdcard/decrypt.txt", JSON.stringify(ehi, null, 4))
	
		return ehi
		
	} else {
		return console.log(ehi)
	}
	
	return ehi
}

console.clear()

const decryptFile = fs.readFileSync("/sdcard/decrypt.txt", "utf-8")

try {
	var file = JSON.parse(decryptFile)
} catch (err) {
	var file = JSON.parse(decryptFile.split('}')[0] + '}')
}

console.log(colors.brightGreen("\nMade With Love By ShayCormac"))
console.log(colors.brightCyan("By ShayStudioLaB\n"))

parseConfig(file, 1)
