const fs = require("fs");
const chalk = require("chalk");
const input = require("prompt-sync")();
const evilscan = require("evilscan");
const exec = require("child_process").exec;
const auth = require("./auth");
require("dotenv").config();

let authLogScan = function(path) {
    console.log("Reading auth.log...");
    const log = fs.readFileSync(path, {encoding:'utf8', flag:'r'});
    console.log("Getting report...");
    const report = auth.analyzeAuthLog(log);
    console.log(chalk.blue("auth.log report:"));
    console.log(chalk.red(`${report.failedIPs.size} IPs attempted a connection.`));
    console.log(chalk.greenBright(`${report.acceptedIPs.size} IPs successfully logged in. They are: ${Array.from(report.acceptedIPs).join(", ")}`));
    console.log(chalk.red("Random SSH connection attempts can be reduced by putting port 22 behind a firewall and only allowing certain IPs to connect."));
    console.log(chalk.yellow("You can set that up by running \"sudo ufw allow from <your ip> to any port 22 proto tcp\""));
}

let removeEmpty = function(arr) {
    let output = [];
    for (let item of arr) {
        if (item !== "") {
            output.push(item);
        }
    }
    return output;
}
let portScan = function() {
    console.log("Running port scan on localhost in range 1-10000");
    let scan = new evilscan({
        target:"127.0.0.1",
        port:'0-10000',
        status:'O', // Timeout, Refused, Open, Unreachable
        banner:false
    });
    let data = [];
    scan.on = scan.on || function(){};

    scan.on('result', (stuff) => {
        data.push(stuff);
    });

    scan.on('error', (err) => {
        throw new Error(err);
    });

    scan.on('done', () => {
        console.log("Done.");
        let open = [];
        for (let port of data) {
            if (port.status === "open") {
                open.push(port.port);
            }
        }
        exec(`sudo ufw status`, (error, stdout, stderr) => {
            if (error) {
                console.log("An error occurred :( ```\n"+error.message+"\n```");
                return;
            }
            if (stderr) {
                console.log("```\n"+stderr+"\n```");
                return;
            }
            let ufw = stdout.split("\n");
            let active = ufw[0].includes("active");
            if (!active) {
                console.log(chalk.red(`${open.length} open ports. UFW firewall is inactive, please consider enabling it through "sudo ufw enable"`));
                return;
            }
            ufw = ufw.slice(4);
            ufw.pop();
            ufw.pop();
            let badlyAllowed = [];
            for (let line of ufw) {
                let info = removeEmpty(line.split(" "));
                if (info[1] === "ALLOW" && info[2] === "Anywhere") {
                    console.log(info);
                    badlyAllowed.push(info[0]);
                }
            }
            if (badlyAllowed.length > 0) {
                console.log(chalk.red(`${open.length} open ports. UFW firewall is active, however port(s) ${badlyAllowed.join(", ")} are allowed from anywhere.`));
            } else {
                console.log(chalk.greenBright(`${open.length} open ports, however all of them are under UFW firewall :)`));
            }
            console.log(chalk.yellow("If ports are intentionally open to the world (for instance, if you got a website running), this is usually"));
            console.log(chalk.yellow("nothing to worry about. However, for best security practices, block or whitelist as many ports as possible."));
        });
    });

    scan.run();
}

console.log(chalk.greenBright("Sentinel vINDEV"));
console.log(chalk.greenBright("Copyright 2021 Dmitry Pleshkov"));
console.log(chalk.blue("Which operation would you like to perform?"));
console.log(chalk.blue("1 - All Scans (default)"));
console.log(chalk.blue("2 - auth.log scan (see who tried to connect remotely)"));
console.log(chalk.blue("3 - port scan (see which ports are open, and how many are protected)"));
console.log(chalk.blue("4 - general security questionnaire (asks questions )"));
let choice = input("> ");
if (choice === "") {
    choice = "1";
}
if (!["1", "2", "3"].includes(choice)) {
    console.log(chalk.red("Invalid choice entered, exiting..."));
    process.exit();
}
if (choice === "1" || choice === "2") {
    let path = input("Enter path to auth.log file (default: /etc/var/auth.log) > ");
    if (path === "") {
        path = "/etc/var/auth.log";
    }
    authLogScan(path);
}
if (choice === "1" || choice === "3") {
    portScan();
}
//const data = fs.readFileSync('./auth.log', {encoding:'utf8', flag:'r'});
//console.log(auth.analyzeAuthLog(data));