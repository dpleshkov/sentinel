let analyzeAuthLog = async function(fileData) {
    let ips = new Set();
    let failedIPs = new Set();
    let acceptedIPs = new Set();
    let lines = fileData.split("\n");
    for (let line of lines) {
        if (line.includes("sshd")) {
            let ip = grabIP(line)
            if (ip !== "") {
                ips.add(ip);
                if (line.includes("Invalid") || line.includes("Disconnected from authenticating user") || line.includes("Unable to negotiate") || line.includes("invalid") || line.includes("Connection closed by authenticating user")) {
                    failedIPs.add(ip);
                }
                if (line.includes("Accepted")) {
                    acceptedIPs.add(ip);
                }
            }

        }
    }
    return {
        IPs: ips,
        failedIPs: failedIPs,
        acceptedIPs: acceptedIPs,
        neitherIPs: new Set([...ips].filter(x => !failedIPs.has(x)))
    };
}

let grabIP = function(line) {
    let words = line.split(" ");
    for (let word of words) {
        if (word.includes(".") && word.split(".").length === 4) {
            return word;
        }
    }
    return "";
}

module.exports.analyzeAuthLog = analyzeAuthLog;