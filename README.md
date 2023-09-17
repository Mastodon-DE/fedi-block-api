# Fedi block API

Used to see which instances block yours.

## software used:

- python 3.10.2

## Installation

```bash
sudo useradd -m fba
sudo mkdir -p /opt/fedi-block-api
sudo chown -R fba:fba /opt/fedi-block-api
sudo -Hu fba git clone TODO: Add github link here /opt/fedi-block-api
cd /opt/fedi-block-api
sudo -Hu fba pip3 install -r requirements.txt
sudo -Hu fba cp blocks_empty.db blocks.db
sudo -Hu fba python3 fetch_instances.py mastodon.social # try a bunch of large servers here
sudo -Hu fba cp config.defaults.json config.json
```


### Install the services

```bash
sudo cp services/* /etc/systemd/system
```

### start the services

```bash
systemctl enable --now fetch_blocks
systemctl enable --now fedi_block_api
```

## Try it out

TODO: Add mastodonDE link here

## License
This Project is licensed und the AGPLv3 License as indicated by the LICENSE file.

### License history

This project WAS "licensed" under the [AGPLv3+NIGGER](https://plusnigger.autism.exposed/) License but as this License violates the Copyright of the Free Software Foundation we have decided that omitting the part in violation of their copyright is enough to be able to use the license.
