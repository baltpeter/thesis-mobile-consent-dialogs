import { join } from 'path';
import yargs from 'yargs';
// @ts-ignore
import dirname from 'es-dirname';

export const argv = yargs(process.argv.slice(2))
    .options({
        platform: { choices: ['android', 'ios'] as const, demandOption: true, group: 'Required options:' },
        apps_dir: { type: 'string', demandOption: true, group: 'Required options:' },

        idevice_ip: {
            type: 'string',
            describe: 'Local IP address of the iDevice to use',
            group: 'iOS options:',
        },
        xcode_org_id: {
            type: 'string',
            describe: 'Team ID of the Apple developer certificate to use',
            group: 'iOS options:',
        },
        xcode_signing_id: {
            type: 'string',
            default: 'Apple Development',
            describe: 'Name of the Apple developer certificate to use',
            group: 'iOS options:',
        },
        device_udid: {
            type: 'string',
            default: 'auto',
            describe: 'Unique device identifier of the device to use',
            group: 'iOS options:',
        },
        device_name: {
            type: 'string',
            default: 'iPhone',
            describe: 'Name of the device to use (hint: `xcrun xctrace list devices`)',
            group: 'iOS options:',
        },
        webdriver_agent_bundle_id: {
            type: 'string',
            default: 'com.facebook.WebDriverAgentRunner',
            describe: 'Bundle ID of the WebDriverAgentRunner to use',
            group: 'iOS options:',
        },
        idevice_root_pw: {
            type: 'string',
            default: 'alpine',
            describe: 'Root password of the iDevice to use',
            group: 'iOS options:',
        },

        mitmdump_path: {
            type: 'string',
            default: join(dirname(), '../../venv/bin/mitmdump'),
            group: 'Optional options:',
        },
        frida_ps_path: {
            type: 'string',
            default: join(dirname(), '../../venv/bin/frida-ps'),
            group: 'Optional options:',
        },

        dev: {
            type: 'boolean',
            default: false,
            describe: 'Run analysis on the app that is currently open',
            group: 'Development options:',
        },
        debug_text: {
            type: 'boolean',
            default: false,
            describe: 'Log the text of all encountered elements',
            group: 'Development options:',
        },
        debug_tree: {
            type: 'boolean',
            default: false,
            describe: 'Log the app source tree at the end',
            group: 'Development options:',
        },
    })
    .check((argv) => {
        for (const arg of ['xcode_org_id', 'idevice_ip']) {
            if (argv.platform === 'ios' && !argv[arg]) throw new Error(`You need to specify \`${arg}\` for iOS.`);
        }
        return true;
    })
    .parseSync();

export type ArgvType = typeof argv;
