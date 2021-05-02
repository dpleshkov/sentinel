const fs = require("fs");
const chalk = require("chalk");
const prompt = require("prompt-sync")();
const evilscan = require("evilscan");
const exec = require("child_process").exec;
const auth = require("./auth");
const util = require("./util");
require("dotenv").config();

(async function(){
    let choice;
    // Title screen
    console.log(chalk.greenBright("SENTINEL v.INDEV"));
    console.log(chalk.greenBright("Copyright 2021 Dmitry Pleshkov"));
    // Do auth.log analysis
    choice = prompt("Would you like to perform a scan of your auth.log to see SSH connection attempts? y/N > ");
    if (choice.toLowerCase().startsWith("y")) {
        console.log("Reading auth.log...");
        const log = fs.readFileSync("/var/log/auth.log", {encoding:'utf8', flag:'r'});
        console.log("Getting report...");
        const report = auth.analyzeAuthLog(log);
        console.log(chalk.blue("auth.log report:"));
        console.log(chalk.red(`${report.failedIPs.size} IPs attempted a connection.`));
        console.log(chalk.greenBright(`${report.acceptedIPs.size} IPs successfully logged in. They are: ${Array.from(report.acceptedIPs).join(", ")}`));
        if (report.failedIPs.size > 10) {
            console.log(chalk.red("Random SSH connection attempts can be reduced by putting port 22 behind a firewall and only allowing certain IPs to connect."));
            console.log(chalk.yellow("You can set that up by running \"sudo ufw allow from <your ip> to any port 22 proto tcp\""));
            choice = prompt("Would you like to do that? y/N > ");
            if (choice.toLowerCase().startsWith("y")) {
                let userIP = util.grabIP((await util.run("who am i|awk '{ print $5}'")).stdout);
                console.log(chalk.yellowBright(`We think your home IP is ${userIP}. Would you like to hide SSH port 22 from anyone but ${userIP}?`));
                console.log(chalk.redBright(`WARNING: THIS ACTION MAY RESULT IN YOUR MACHINE BECOMING UNREACHABLE`));
                choice = prompt("Are you sure? y/N > ");
                if (choice.toLowerCase().startsWith("y")) {
                    console.log((await util.run(`sudo ufw allow from ${userIP} to any port 22 proto tcp`)).stdout);
                } else {
                    console.log("Cancelled action.");
                }
            }
        }
    }
    // Do port analysis
    choice = prompt("Would you like to perform a scan for open ports? y/N > ");
    if (choice.toLowerCase().startsWith("y")) {
        console.log("Running port scan in range 0-49151");
        let scan = await util.portScan();
        let open = new Set();
        for (let port of scan) {
            if (port.status === "open") {
                open.add(String(port.port));
            }
        }
        let unfiltered = new Set();
        let filtered = new Set();
        let ufw = await util.getUFWStatus();
        if (ufw.status === "enabled") {
            for (let port of ufw.ports) {
                if (port.status === "ALLOW" && port.from.includes("Anywhere")) {
                    unfiltered.add(port.port);
                } else {
                    filtered.add(port.port);
                }
            }
        }
        let both = new Set([...open].filter(x => filtered.has(x)));
        console.log(chalk.red(`Detected ${open.size} open ports, of which ${both.size} are either blocked or filtered by UFW firewall.`));
        if (ufw.status === "enabled") {
            console.log(chalk.red(`Allowed ports through UFW: ${Array.from(unfiltered).join(", ")}`));
        } else {
            console.log(chalk.red(`UFW Firewall is DISABLED. These ports remain open: ${Array.from(open).join(", ")}. Consider enabling the firewall with "sudo ufw enable"`));
        }
    }
})();