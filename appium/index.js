const wdio = require('webdriverio');

async function main() {
    const client = await wdio.remote({
        path: '/wd/hub',
        port: 4723,
        capabilities: {
            platformName: 'Android',
            platformVersion: '11',
            deviceName: 'appium-ma',
        },
        logLevel: 'warn',
    });

    const els = await client.findElements('xpath', '//*');
    for (const el of els) {
        const a = await client.getElementAttribute(el.ELEMENT, 'name');
        console.log(a);
    }

    await client.deleteSession();
}

main();
