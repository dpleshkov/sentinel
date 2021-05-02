const Evilscan = require('evilscan');

const options = {
    target:'52.53.110.54',
    port:'0-1000',
    status:'RO', // Timeout, Refused, Open, Unreachable
    banner:true
};

const evilscan = new Evilscan(options);

evilscan.on('result',data => {
    // fired when item is matching options
    console.log(data);
});

evilscan.on('error', err => {
    throw new Error(data.toString());
});

evilscan.on('done', () => {
    // finished !
});

evilscan.run();