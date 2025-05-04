use tokio::time::Instant;
use twitch_irc::login::StaticLoginCredentials;
use twitch_irc::{ClientConfig, SecureTCPTransport, TwitchIRCClient};
use twitch_irc::message::{IRCMessage, ServerMessage};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use reqwest::Error;
use regex::Regex;
use serde_json::Value;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use rand::{rng, Rng};
use std::process;
use clap::{Command as clapCommand, Arg};
use color_art::Color;
use std::sync::Arc;
use tokio::sync::Mutex;

const VERSION: &str = "v0.0.3a";
const OAUTH_TOKEN: &str = ""; // enter token here
const CLIENTID: &str = "";
const CHANNELS: [&str; 5] = ["kamychine", "kamythol", "btmc", "znxtech", "exersalza"];

#[derive(Serialize, Deserialize, Debug)]
struct ChannelInfo {
    data: Vec<Channel>,
    pagination: Pagination,
}
#[derive(Serialize, Deserialize, Debug)]
struct Channel {
    broadcaster_language: String,
    broadcaster_login: String,
    display_name: String,
    game_id: String,
    game_name: String,
    id: String,
    is_live: bool,
    tag_ids: Vec<String>,
    tags: Vec<String>,
    thumbnail_url: String,
    title: String,
    started_at: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct Pagination {
}
#[derive(Serialize, Deserialize, Debug)]
struct User {
    user_login: String,
    last_timestamp: String,
    first_timestamp: String,
}

#[derive(Clone)]
pub struct Bot {
    last_msg: String,
}

impl Bot {
    pub fn new() -> Self {
        Bot {
            last_msg: String::new(),
        }
    }

    pub async fn say(
        &mut self, 
        channel: &str,
        client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
        mut msg: String, 
        ) {
        if self.last_msg == msg {
            msg.push_str(" 󠀀 ");
        }
        if channel != "btmc" {
            client.say(channel.to_string(), format!("{}", msg)).await.unwrap();
        } else {
            match is_live(channel.to_string(), OAUTH_TOKEN.to_string(), CLIENTID.to_string()).await {
                Ok(false) => {
                    client.say(channel.to_string(), format!("{}", msg)).await.unwrap();
                }
                Ok(true) => {
                    println!("Command ran in channel live ({})", &channel.to_string());
                }
                _ => {

                }
            }
        }
        // client.say(channel.to_string(), format!("{}", msg)).await.unwrap();
        self.last_msg = msg.to_string();
    }
}

// im gonna jump into the void in minecraft

#[derive(Clone)]
pub struct BotHandle {
    bot: Arc<Mutex<Bot>>,
}

impl BotHandle {
    pub fn new(bot: Arc<Mutex<Bot>>) -> Self {
        BotHandle { bot }
    }

    pub async fn say(
        &self,
        channel: &str,
        client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
        msg: String,
    ) {
        let mut bot = self.bot.lock().await;
        bot.say(channel, &client, msg).await;
    }
}

pub struct BotApp {
    pub client: Arc<TwitchIRCClient<SecureTCPTransport, StaticLoginCredentials>>, 
    pub bot_handle: BotHandle,
}

impl BotApp {
    pub fn new(
        client: TwitchIRCClient<SecureTCPTransport, StaticLoginCredentials>,
        bot_handle: BotHandle,
    ) -> Self {
        BotApp {
            client: Arc::new(client),
            bot_handle,
        }
    }
}

#[tokio::main]
pub async fn main() {
    if OAUTH_TOKEN.is_empty() {
        panic!("Oauth token value is empty br, compile with token");
    }

    let login_name = "kamychine".to_owned();
    
    let config: ClientConfig<StaticLoginCredentials> = ClientConfig::new_simple(
        StaticLoginCredentials::new(login_name, Some(OAUTH_TOKEN.to_owned()))
    );
    
    let (mut incoming_messages, client) =
        TwitchIRCClient::<SecureTCPTransport, StaticLoginCredentials>::new(config);

    // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    let client_clone = client.clone();
    let bot = Arc::new(Mutex::new(Bot::new()));
    let bot_handle = BotHandle::new(Arc::clone(&bot));
    let bot_app = BotApp::new(client.clone(), bot_handle.clone());

    let irc_message = IRCMessage::parse(":tmi.twitch.tv PING").unwrap();
    let server_message = ServerMessage::try_from(irc_message).unwrap();

    // join channels
    for i in 0..CHANNELS.len() {
        client_clone.join(CHANNELS[i].to_owned()).unwrap();
    }

    // idk how to do uptime in handle_command()
    let uptime = Instant::now();

    let join_handle = tokio::spawn(async move {
        while let Some(message) = incoming_messages.recv().await {
            match message {
            ServerMessage::Privmsg(msg) => {
                let msg_text = msg.clone().message_text;
                let msg_channel = msg.clone().channel_login;

                println!("[{}] #{} {}: {}", msg.server_timestamp, msg.channel_login, msg.sender.name, msg.message_text);
                
                if msg.message_text.starts_with("-") {
                    tokio::spawn({
                    let bot_handle = bot_app.bot_handle.clone();
                    let client = Arc::clone(&bot_app.client);
                    async move {
                    handle_command(bot_handle, &msg.message_text, &msg.channel_login, client, &msg.sender.name).await;
                    }
                });
                }
                // idk if this is necessary lol
                tokio::spawn({
                    let bot_handle = bot_app.bot_handle.clone();
                    let client = Arc::clone(&bot_app.client);
                    async move {
                        if msg_text.contains("bored") || msg_text.contains("board") {
                            let rng100 = rand::rng().random_range(1..=100);
                            println!("{}", rng100);
                            if rng100 == 3 { bot_handle.say(&msg_channel, &client, format!("board")).await; }

                        }
                        if msg_text.starts_with("augh") || msg_text.contains(" augh") {
                            let rng500 = rand::rng().random_range(1..=500);
                            println!("{}", rng500);
                            if rng500 == 3 { bot_handle.say(&msg_text, &client, format!("augh")).await; }

                        }
                        let re = Regex::new(r"\-uptime\b").unwrap();
                        if re.is_match(&msg_text) {
                            let ut = uptime.elapsed().as_secs();
                            let ut_days: f32 = (ut as f32) / 60.0 / 60.0 / 24.0;
                            let ut_hours = (ut_days - ut_days.floor()) * 24.0;
                            let ut_min = (ut_hours - ut_hours.floor()) * 60.0;
                            bot_handle.say(&msg_channel, &client, format!("🕐 {}d {}h {}m {}s", ut_days.floor() as i32, ut_hours.floor() as i32, ut_min.floor() as i32, (ut % 60))).await;
                        }
                    }
                });
            },
            ServerMessage::Whisper(msg) => {
                println!("(w) {}: {}", msg.sender.name, msg.message_text);
            },
            _ => {}
            }
        }
    });
    
    match server_message {
        ServerMessage::Ping { .. } => println!("Connected."),
        ServerMessage::Reconnect { .. } => println!("Reconnected."),
        _ => {
        }
    }
    
    join_handle.await.unwrap();

}

async fn is_live(channel: String, token: String, clientid: String) -> Result<bool, anyhow::Error> {
    let req = format!("https://api.twitch.tv/helix/search/channels?query={}&first=1", channel);
    let client = reqwest::Client::new();
    let data = client
        .get(req)
        .header("Authorization", format!("Bearer {token}"))
        .header("Client-Id", clientid)
        .send()
        .await?
        .json::<ChannelInfo>()
        .await?;

    Ok(data.data.first().unwrap().is_live)
}

// UGLY CODE!!!!!
async fn handle_command (
    bot: BotHandle,
    message_text: &str,
    channel: &str,
    client: Arc<TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>>,
    user: &str
) {
    let inst = Instant::now();

    // i fucking despise invisble characters FUCK chatterino FUCK chatsen
    let re_invis = Regex::new(r"󠀀 | 󠀀").unwrap();
    let message_text = re_invis.replace_all(message_text, "");
    let message_text = &message_text.replace("  ", " ");

    let mut parts = message_text.splitn(3, ' ');
    if let Some(command) = parts.next() {
        let mut args: Vec<&str> = parts.collect();
        args.retain(|s| !s.is_empty());
        
        // experiment
        let mut parsed = vec!["kamychine", command.trim_start_matches('-')];
        parsed.extend(&args);
        let matches = build_parser().try_get_matches_from(parsed);
        // ---

        if user == "kamythol" {
            match command {
                "-join" | "-groupadd"  => {
                    if let Some(name) = args.get(0) {
                        client.join(name.to_string().replace("|", "")).unwrap();
                        println!("Joined {}", name);
                    }
                }
                "-leave" | "-groupdel" => {
                    if let Some(name) = args.get(0) {
                        client.part(name.to_string().replace("|", ""));
                        println!("Left {}", name);
                    }
                }
                "-kill" | "-shutdown" => {
                    if let Some(time) = args.get(0) {
                        sleep(Duration::from_secs(time.to_string().parse().unwrap()));
                        process::exit(0x0100);
                    } else {
                        process::exit(0x0100);
                    }
                }
                "-restart" | "-reboot" => {
                    restart();
                }
                "-expiration" => {
                    expiration_check(bot.clone(), &client, channel).await.unwrap();
                }
                _ => {
                }
            }
        }
        
        match command {
            "-version" | "-v" => {
                bot.say(channel, &client, format!("{}", VERSION.to_string())).await;
            }
            "-help" | "-h" => {
                bot.say(channel, &client, format!("https://dub.sh/kambot-help")).await;
            }
            "-ip" => {
                bot.say(channel, &client, format!("https://niko.wav.blue/")).await;
            }
            "-whoami" => {
                bot.say(channel, &client, format!("{user}")).await;
            }
            "-groups" | "-channels" => {
                let joined = CHANNELS.iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
                    .join(" ");
                bot.say(channel, &client, format!("{}", spoof_user(&joined))).await;
            }
            "-about" => {
                bot.say(channel, &client, format!("random shit go! bot made in Rust 😲😲🚀🚀😲😲😲😲😲🚀🚀🚀🚀🚀")).await;
            }
            "-ping" => {
                bot.say(channel, &client, format!("pong")).await;

            }
            "-chatting" => {
                bot.say(channel, &client, format!("Chatting")).await;
            }
            "-battery" => {
                match sh_chatlog("acpi", "", "") {
                    Ok(result) => {
                        let batt = result.replace("Battery 0: ", "");
                        bot.say(channel, &client, format!("{}", batt)).await;

                    }
                    Err(error) => {
                        println!("{}", error);
                        bot.say(channel, &client, format!("Error: Something went wrong.")).await;
                    }
                }
            }
            "-randommsg" | "-rmsg" => {
                if let Some(name) = args.get(0) {
                    let is_self = name == &"-self" || name == &"-s";
                    let u = if is_self { user.to_string() } else { name.to_string() };
                    if let Some(search_str) = args.get(1) {
                        randomuser_search(bot, u.to_string(), search_str.to_string(), &client, channel).await.unwrap();
                    } else {
                        randomuser(bot, u.to_string(), &client, channel).await.unwrap();
                    }
                } else {
                    let _ = randomall(bot, &client, channel).await;
                }
            }
            "-rsearch" | "-rfind" => {
                if let Some(arg1) = args.get(0) {
                    let is_self = arg1 == &"-self" || arg1 == &"-s";
                    if let Some(arg2) = args.get(1) {
                        if is_self {
                            randomsearch(bot, &client, channel, format!("]\\s+{}: {}", user.to_string(), arg2.to_string())).await.unwrap();
                        } else {
                            randomsearch(bot, &client, channel, format!("{} {}", arg1.to_string(), arg2.to_string())).await.unwrap();
                        }
                    } else {
                        if is_self {
                            randomsearch(bot, &client, channel, format!("]\\s+{}: ", user.to_string())).await.unwrap();
                        } else {
                            randomsearch(bot, &client, channel, arg1.to_string()).await.unwrap();
                        }
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -rfind [pattern]")).await;
                }
            }
            "-latest" => {
                if let Some(name) = args.get(0) {
                    if let Some(search_str) = args.get(1) {
                        latest_search(bot, name.to_string(), search_str.to_string(), &client, channel).await.unwrap();
                    } else {
                        latest(bot, name.to_string(), &client, channel).await.unwrap();
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -latest [username] [string]")).await;
                }
            }
            "-ocount2" => {
                match matches {
                    Ok(m) => {
                        if let Some(sub_m) = m.subcommand_matches("ocount2") {
                            let user = sub_m.get_one::<String>("user").unwrap();
                            let pattern = sub_m.get_one::<String>("pattern").unwrap();
                            countuser(bot, user.to_string(), pattern.to_string(), &client, channel).await.unwrap();
                        }
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        bot.say(channel, &client, format!("Something went wrong. Are the arguments correct?")).await;
                        // bot.say(channel, &client, format!("{e}")).await;
                    }
                }
            }
            "-onlinecount" | "-ocount" => {
                if let Some(name) = args.get(0) {
                    if let Some(search_str) = args.get(1) {
                        countuser(bot, name.to_string(), search_str.to_string(), &client, channel).await.unwrap();
                    } else {
                        bot.say(channel, &client, format!("Missing search string. Usage: -ocount [username] [search pattern (no regex)]")).await;
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -ocount [username] [search pattern (no regex)]")).await;
                }
            }
            "-onlinesearch" | "-onlinefind" | "-osearch" | "-ofind" => {
                if let Some(name) = args.get(0) {
                    if let Some(search_str) = args.get(1) {
                        searchuser(bot, name.to_string(), search_str.to_string(), &client, channel).await.unwrap();
                    } else {
                        bot.say(channel, &client, format!("Missing search string. Usage: -osearch [username] [search pattern (regex: ❌)]")).await;
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -osearch [username] [search pattern (regex: ❌)]")).await;
                }
            }
            "-count" => {
                if let Some(pattern) = args.get(0) {
                    if let Some(pattern2) = args.get(1) {
                        let patt = format!("{} {}", pattern.to_string(), pattern2.to_string());
                        match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", &patt.replace("-", r"\-")) {
                            Ok(count) => {
                                bot.say(channel, &client, format!("Found {} messages.", count)).await;
                            }
                            Err(error) => {
                                eprintln!("{}", error);
                                bot.say(channel, &client, format!("Error: Something went wrong.")).await;
                            }
                        }
                    } else {
                        match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", &pattern.replace("-", r"\-")) {
                            Ok(count) => {
                                bot.say(channel, &client, format!("Found {} messages.", count)).await;
                            }
                            Err(error) => {
                                eprintln!("{}", error);
                                bot.say(channel, &client, format!("Error: Something went wrong.")).await;
                            }
                        }
                    }
                } else {
                    bot.say(channel, &client, format!("Requires a search pattern. (regex supported)")).await;
                }
            }
            "-search" | "-find" => {
                if let Some(name) = args.get(0) {
                    match name {
                        &"-c" => {
                            if let Some(pattern) = args.get(1) {
                                match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", &pattern.replace("-", r"\-")) {
                                    Ok(count) => {
                                        bot.say(channel, &client, format!("Found {} messages.", count)).await;
            
                                    }
                                    Err(error) => {
                                        println!("{}", error);
                                        bot.say(channel, &client, format!("bruh omething went wrong.")).await;
                                    }
                                }
                            } else {
                                bot.say(channel, &client, format!("Requires a search pattern. (regex supported)")).await;
                            }
                        }
                        &"-a" => {
                            if let Some(pattern) = args.get(1) {
                                match sh_chatlog("/home/frthr/up-chatlog.sh", "-a", &pattern.replace("-", r"\-")) {
                                    Ok(link) => {
                                        bot.say(channel, &client, format!("{}", link)).await;
            
                                    }
                                    Err(error) => {
                                        println!("{}", error);
                                        // bot.say(channel, &client, format!("Error: {}", error)).await;
                                        bot.say(channel, &client, format!("bruh something went wrong.")).await;
                                    }
                                }
                            } else {
                                bot.say(channel, &client, format!("Requires a search pattern. (regex supported)")).await;
                            }
                        }
                        &"-o" => {
                            if let Some(pattern) = args.get(1) {
                                
                                match sh_chatlog("/home/frthr/up-chatlog.sh", "-o", &pattern.replace("-", r"\-")) {
                                    Ok(count) => {
                                        bot.say(channel, &client, format!("Found {} occurrences.", count)).await;
            
                                    }
                                    Err(error) => {
                                        println!("{}", error);
                                        // bot.say(channel, &client, format!("Error: {}", error)).await;
                                        bot.say(channel, &client, format!("bruh something went wrong.")).await;
                                    }
                                }
                            } else {
                                bot.say(channel, &client, format!("Requires a search pattern. (regex supported)")).await;
                            }
                        }
                        _ => {
                            bot.say(channel, &client, format!("Usage: -search [-a|-c|-o] [search pattern (regex: ✅)]")).await;
                        }
                        
                    }
                   
              } else {
                    bot.say(channel, &client, format!("Usage: -search [-a|-c|-o] [search pattern (regex: ✅)]")).await;
              }
            }
            "-ucount" | "-usercount" => {
                if let Some(user) = args.get(0) {
                    if let Some(pattern) = args.get(1) {
                        local_countuser(bot, &client, channel, user.to_string(), pattern.to_string()).await.unwrap();
                    } else {
                        local_countuser(bot, &client, channel, user.to_string(), "".to_string()).await.unwrap();
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -ucount [username] [pattern]")).await;
                }
            }
            "-usearch" | "-ufind" => {
                if let Some(user) = args.get(0) {
                    if let Some(pattern) = args.get(1) {
                        local_searchuser(bot, &client, channel, user.to_string(), pattern.to_string()).await.unwrap();
                    } else {
                        local_searchuser(bot, &client, channel, user.to_string(), "".to_string()).await.unwrap();
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -usearch [username] <pattern>")).await;
                }
            }
            "-rooc" | "-randomooc" => {
                random_ooc(bot, &client, channel).await.unwrap();
            }
            "-stats" => {
                match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", "]\\s+kamychine: .*") {
                    Ok(count) => {
                        bot.say(channel, &client, format!("Chatting {} bot messages have been sent. {} commands have been run.", count, countcmds())).await;

                    }
                    Err(error) => {
                        eprintln!("{}", error);
                        bot.say(channel, &client, format!("bruh something went wrong.")).await;
                    }
                }
            }
            "-get" => {
                if let Some(day) = args.get(0) {
                    match sh_chatlog("/home/frthr/up-chatlog.sh", "-f", day) {
                        Ok(link) => {
                            bot.say(channel, &client, format!("{link}")).await;
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            bot.say(channel, &client, format!("bruh something went wrong.")).await;
                        }
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -get yyyy-mm-dd")).await;
                }
            }
            "-namehistory" => {
                if let Some(name) = args.get(0) {
                    namehistory(bot, name.to_string(), &client, channel).await.unwrap();
                } else {
                    bot.say(channel, &client, format!("Usage: -namehistory [username]")).await;
                }
            }
            "-color" => {
                if let Some(arg1) = args.get(0) {
                    if let Some(arg2) = args.get(1) {
                        if arg1 == &"-alt" || arg1 == &"-a" {
                            match getcolor_alt(bot.clone(), arg2.to_string(), &client, channel).await {
                                Ok(link) => {
                                    bot.say(channel, &client, format!("{link}")).await;
                                }
                                Err(e) => {
                                    bot.say(channel, &client, format!("{e}")).await;
                                }
                            }
                            return
                        }
                        let concat = format!("{} {}", arg1.to_string(), arg2.to_string());
                        match getcolor(bot.clone(), concat, &client, channel).await {
                            Ok(color) => {
                                bot.say(channel, &client, format!("{color}")).await;
                            }
                            Err(e) => {
                                bot.say(channel, &client, format!("{e}")).await;
                            }
                        }
                        return
                    }
                    match getcolor(bot.clone(), arg1.to_string(), &&client, channel).await {
                        Ok(color) => {
                            bot.say(channel, &client, format!("{color}")).await;
                        }
                        Err(e) => {
                            bot.say(channel, &client, format!("{e}")).await;
                        }
                    }
                } else {
                    bot.say(channel, &client, format!("Usage: -color [rgb[a](x, x, x) | #hex | hsl[a](x, x, x) | colorname | mostotherformats]")).await;
                }
            }
            _ => {
            }
        }
        println!("Took {}ms", inst.elapsed().as_millis());
    }
}

// does this do anything
fn restart() {
    use std::os::unix::process::CommandExt;
    Command::new("/proc/self/exe").exec();
}

// ?
fn build_parser() -> clapCommand {
    clapCommand::new("kamychine")
        .subcommands([
            clapCommand::new("ocount2")
                .arg(Arg::new("user")
                    .required(true)
                    .help("username")
                    .short('u').long("user"))
                .arg(Arg::new("pattern")
                    .required(true)
                    .short('p').long("pattern")
                    .help("search pattern")),
            clapCommand::new("search")
                .arg(Arg::new("user")
                    .required(false)
                    .short('u').long("user")
                    .help("username"))
                .arg(Arg::new("pattern")
                    .required(true)),
                
        ])
}

fn sh_chatlog(path: &str, args: &str, patt: &str) -> Result<String, String> {
    println!("path: {:?}, args: {:?}, pattern: {:?}", path, args, patt);
    let output = Command::new(path)
        .arg(args)
        .arg(patt)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;
    println!("{:?}", output);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("{:?}", stdout);
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(stderr)
    }
}

async fn randomsearch (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str,
    pattern: String
) -> Result<(), String> {
    let patt = format!("{pattern}");
    match sh_chatlog("/home/frthr/up-chatlog.sh", "-r", &patt.replace("-", r"\-")) {
        Ok(mut text) => {
            if text.len() == 0 {
                bot.say(channel, &client, format!("reeferSad No matches.")).await;
            } else {
                text = processtext(text);
                bot.say(channel, &client, format!("{}", text.trim_end())).await;
            }
            Ok(())
        }
        Err(error) => {
            bot.say(channel, &client, format!("bruh something went wrong.")).await;
            eprintln!("Error: {error}");
            Err(error)
        }
    }
}

async fn random_ooc (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), anyhow::Error> {
    if let Some(mut file_path) = dirs::config_dir() {
        file_path.push("kamychine");
        file_path.push("ooc.txt");
        
        if !file_path.exists() { // wha tthe ufck is the point iof this
            File::create(file_path.clone()).expect(&format!("Failed to create file @ {:?}", file_path));
        }

        let mut file = File::open(file_path).expect("Couldn't open text file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let lines: Vec<&str> = contents.lines().collect();
        if !lines.is_empty() {
            let line = lines[rng().random_range(0..lines.len())];
            println!("{line}");
            bot.say(channel, &client, format!("{}", line)).await;
        } else {
            println!("ooc list is empty");
            bot.say(channel, &client, format!("erm")).await;
        }
    }
    Ok(())
}

async fn local_searchuser (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str,
    user: String, 
    pattern: String
) -> Result<(), String> {
    let patt = format!("]\\s+{user}: {pattern}");
    
    match sh_chatlog("/home/frthr/up-chatlog.sh", "-a", &patt.replace("-", r"\-")) {
        Ok(link) => {
            bot.say(channel, &client, format!("{link}")).await;
            Ok(())
        }
        Err(error) => {
            bot.say(channel, &client, format!("Something went wrong.")).await;
            println!("Error: {error}");
            Err(error)
        }
    }
}

async fn searchuser (
    bot: BotHandle,
    mut user: String, 
    mut search: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), reqwest::Error> {
    user = user.replace("|", "");

    let re = Regex::new(r"\s").unwrap();
    search = re.replace_all(&search, "%20").to_string();

    bot.say(channel, &client, format!("https://logs.nadeko.net/channel/btmc/user/{}/search?q={}", user, search)).await;
    Ok(())
}

async fn randomall (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), reqwest::Error> {
    println!("Requesting a random message from the channel");
    let req = format!("https://logs.nadeko.net/channel/btmc/random");
    let mut body = reqwest::get(req.clone()).await?.text().await?;

    loop {
        // reroll bot msgs
        if Regex::new(r"\] #btmc (streamelements|kamychine|sheppsubot|bigtimemassivecash|sheepposubot|l3lackshark):").unwrap().is_match(&body) {
            println!("rerolling bot message");
            body = reqwest::get(&req).await?.text().await?;
            continue;
        } else if fuckbots(body.to_owned()) { // reroll bot cmd messages
            println!("rerolling msg: {}", body.trim_end());
            body = reqwest::get(&req).await?.text().await?;
            continue;
        } else {
            body = processtext(body);
            bot.say(channel, &client, format!("{}", body)).await;
            println!("\"{}\"", body.trim_end());
        }
        break
    }
    Ok(())
}

async fn randomuser (
    bot: BotHandle,
    mut user: String, 
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), anyhow::Error> {
    user = user.replace("|", "");

    println!("Requesting random message from {}: ", user);
    let req = format!("https://logs.nadeko.net/channel/btmc/user/{}/random", user);
    let response = reqwest::get(req.clone()).await?;
    let mut body = reqwest::get(req.clone()).await?.text().await?;
    
    if response.status().is_success() {
        for attempt in 1..5 {
            if fuckbots(body.to_owned()) {
                println!("rerolling msg (try {}): {}", attempt, body.trim_end());
                body = reqwest::get(&req).await?.text().await?;
                continue;
            }
            body = processtext(body);
            bot.say(channel, &client, format!("{}", body.trim_end())).await;
            println!("\"{}\"", body.trim_end());
            break
        }
    } else {
        eprintln!("{}", response.status());
        bot.say(channel, &client, format!("reeferSad [{}] No results.", response.status())).await;
    }
    
    Ok(())

}

async fn randomuser_search (
    bot: BotHandle,
    mut user: String,
    mut search: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str,
) -> Result<(), reqwest::Error> {
    user = user.replace("|", "");

    let re = Regex::new(r"\s").unwrap();
    search = re.replace_all(&search, "%20").to_string();

    println!("Requesting logs from {user} containing {search}");
    let req = format!("https://logs.nadeko.net/channel/btmc/user/{}/search?q={}", user, search);
    println!("{req}");
    let response = reqwest::get(req.clone()).await?;
    let mut body = reqwest::get(req.clone()).await?.text().await?;
    let mut body_clone = body.clone();
    body_clone = body_clone.trim().to_string();
    
    let lines: Vec<&str> = body_clone.lines().collect();
    if response.status().is_success() {
        for attempt in 1..=3 {
            let rng = rng().random_range(0..lines.len());
            let line = lines[rng];
            if fuckbots(line.to_string()) {
                println!("rerolling msg [{}] (try {}): {}", rng, attempt, line.trim_end());
                body.clear();
                body = reqwest::get(&req).await?.text().await?;
                if attempt == 3 {
                    bot.say(channel, &client, format!("it's mostly just bot commands br (i'll add a way to disable this filter someday)")).await;
                }
                continue;
            }
            // println!("\"{}\"", line.trim_end());
            let line = &processtext(line.to_string());
            bot.say(channel, &client, format!("{}", line)).await;
            break
        }
    } else {
        eprintln!("{}", response.status());
        bot.say(channel, &client, format!("reeferSad [{}] No results.", response.status())).await;
    };
    Ok(())
}

// async fn countemote(
// ) -> Result<(), anyhow::Error> {
//     let req = format!("https://api.streamelements.com/kappa/v2/chatstats/btmc/stats?limit=5");
//     let data = reqwest::get(req)
//         .await?
//         .text()
//         .await?;
    
//     let v: Value = serde_json::from_str(&data)?;
//     println!("{}", v);
//     println!("{}", v["chatters"][1]["name"].as_str().unwrap());
//     Ok(())
// }

async fn countuser (
    bot: BotHandle,
    mut user: String, 
    mut search: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
    ) -> Result<(), reqwest::Error> {
    user = user.replace("|", "");

    let re_search = Regex::new(r"\s").unwrap();
    search = re_search.replace_all(&search, "%20").to_string();

    let req = format!("https://logs.nadeko.net/channel/btmc/user/{}/search?q={}", user, search);
    let body = reqwest::get(req)
        .await?
        .text()
        .await?;
    
    let mut linecount: i32 = 0;
    for _l in body.lines() {
        linecount += 1;
    }
    println!("Found {} messages.", linecount);
    bot.say(channel, &client, format!("Found {} messages from @{} containing '{}'.", linecount, spoof_user(&user), search.replace("%20", " "))).await;
    Ok(())
}

async fn local_countuser (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str,
    user: String, 
    pattern: String
) -> Result<(), String>  {
    let patt = format!("]\\s+{user}: {pattern}");
    
    match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", &patt.replace("-", r"\-")) {
        Ok(count) => {
            bot.say(channel, &client, format!("{count}")).await;
            Ok(())
        }
        Err(error) => {
            bot.say(channel, &client, format!("bruh something went wrong.")).await;
            println!("Error: {error}");
            Err(error)
        }
    }
}

async fn latest (
    bot: BotHandle,
    mut user: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), Error> {
    
    user = user.replace("|", "");
    println!("Requesting latest message from {}", &user);

    let req = format!("https://logs.nadeko.net/channel/btmc/user/{}?reverse=true&limit=1", &user);
    let mut body = reqwest::get(req)
        .await?
        .text()
        .await?;

    body = processtext(body);
    bot.say(channel, &client, format!("{}", body)).await;
    Ok(())
}

async fn latest_search (
    bot: BotHandle,
    mut user: String,
    mut search: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), Error> {
    
    user = user.replace("|", "");
    search = search.replace(" ", "%20");
    println!("Requesting latest message from {}", &user);

    let req = format!("https://logs.nadeko.net/channel/btmc/user/{}/search?q={}&reverse=true&limit=1", &user, &search);
    let mut body = reqwest::get(req)
        .await?
        .text()
        .await?;

    body = processtext(body);
    bot.say(channel, &client, format!("{}", body)).await;
    Ok(())
}

async fn namehistory (
    bot: BotHandle,
    mut user: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<(), anyhow::Error> {
    user = user.replace("|", "");
    println!("Getting userid of {}", user);

    let user_req = format!("https://logs.nadeko.net/channel/btmc/user/{}/stats", &user);
    let user_stats_res = reqwest::get(user_req.clone()).await?;
    let user_stats = reqwest::get(user_req).await?.text().await?;

    if user_stats_res.status().is_success() {
        let v: Value = serde_json::from_str(&user_stats)?;
        let history_req = format!("https://logs.nadeko.net/namehistory/{}", v["userId"].as_str().unwrap());
        let names: Vec<User> = reqwest::get(history_req.clone()).await?.json::<Vec<User>>().await?;
        
        let mut namelist = String::new();
        for name in names {
            namelist.push_str(&format!("{} ", spoof_user(&name.user_login)));
        }
        bot.say(channel, &client, format!("{namelist}")).await;
    } else {
        bot.say(channel, &client, format!("reeferSad [{}] No results.", user_stats_res.status())).await;
    }
    Ok(())

}   

async fn getcolor (
    bot: BotHandle,
    color: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<String, anyhow::Error> {
    println!("{color}");
    let hex = Color::from_str(&color)?;
    let color_req = format!("https://www.colorhexa.com/{}.png", hex.hex_full().replace("#", ""));
    let color_res = reqwest::get(color_req.clone()).await?;
    if color_res.status().is_success() {
        return Ok(color_req);
    } else {
        bot.say(channel, &client, format!("something went wrong bruh")).await;
        
    }
    Ok(color_req)
} 

// shitass

async fn getcolor_alt (
    bot: BotHandle,
    color: String,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str
) -> Result<String, anyhow::Error> {
    let link = Command::new("curl")
        .args(["-sL", "-o", "/dev/null", "-X", "POST", "https://www.colorhexa.com/color.php", 
        "-d", &format!("color-picker=%23000000&c={}&h=h", color.replace(" ", "+").replace("#", "")), 
        "-w", "%{url_effective}"])
        .output()?;

    println!("{:?}", link);

    let mut stdout = String::from_utf8_lossy(&link.stdout).to_string();
    if link.status.success() {
        if stdout == "https://www.colorhexa.com/" {
            return Ok(format!("not a valid color bruh"));
        }
        stdout = format!("{stdout}.png");
        return Ok(stdout);
    }

    let link_req = reqwest::get(stdout.clone()).await?; 

    if link_req.status().is_success() {
        return Ok(stdout)
    } else {
        bot.say(channel, &client, format!("not a valid color bruh")).await;
    }
    Ok(format!("e"))
    
}

fn spoof_user(user: &str) -> String {
    let patt = Regex::new(r"").unwrap();
    let letters: Vec<&str> = patt.split(user).collect();
    let res = letters.iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join("͏");
    res
}

fn processtext(mut body: String) -> String {
    let inst = Instant::now();
    let re_user_sender = Regex::new(r"\]\s+(#btmc )?(?<username>\w+):").unwrap();
    let re_user_at = Regex::new(r"(?<userat> @\w+)").unwrap();
    
    let Some(username_cap) = re_user_sender.captures(&body) else {return String::from("")};
    let user_at_string = re_user_at
        .captures(&body)
        .map(|cap| cap["userat"].to_string())
        .unwrap_or_else(|| String::from(""));
    
    // ping spoofing 14
    let mut username_string = username_cap["username"].to_string();
    username_string = format!("] {}:", spoof_user(&username_string));
    
    body = re_user_sender.replace(&body, username_string).to_string();
    body = re_user_at.replace_all(&body, spoof_user(&user_at_string)).to_string();
    
    println!("Finished body process in {}ms", inst.elapsed().as_millis());
    body
}

fn fuckbots(string: String) -> bool { // true if bot cmd, false otherwise
    let botcmds = ["!", "-", "$"];
    let re_content = Regex::new(r"\] #btmc.*: (?<content>.*)").unwrap();
    let Some(content_cap) = re_content.captures(&string) else {return false};
    let content = content_cap["content"].to_string();
    return botcmds.iter().any(|cmd| content.starts_with(cmd));
}

async fn expiration_check (
    bot: BotHandle,
    client: &TwitchIRCClient<SecureTCPTransport, twitch_irc::login::StaticLoginCredentials>,
    channel: &str,
) -> Result<(), anyhow::Error> {
    let req = format!("https://id.twitch.tv/oauth2/validate");
    let reqclient = reqwest::Client::new();
    let data = reqclient
        .get(req)
        .header("Authorization", format!("OAuth {OAUTH_TOKEN}"))
        .send()
        .await?.text().await?;

    let v: Value = serde_json::from_str(&data)?;
    let expires_in = v["expires_in"].as_u64().unwrap();
    
    let d: f32 = (expires_in as f32) / 60.0 / 60.0 / 24.0;
    let h = (d - d.floor()) * 24.0;
    let m = (h - h.floor()) * 60.0;
    bot.say(channel, &client, format!("🕐 {}d {}h {}m {}s", d.floor() as i32, h.floor() as i32, m.floor() as i32, (expires_in % 60))).await;
    
    Ok(())
}

fn countcmds() -> String {
    match sh_chatlog("/home/frthr/up-chatlog.sh", "-c", "]\\s+\\w+: -(rooc|stats|randomooc|ufind|rfind|usearch|ucount|usercount|search|find|count|onlinesearch|onlinefind|osearch|ofind|onlinecount|ocount|ocount2|latest|rmsg|randommsg|battery|chatting|ping|about|groups|channels|whoami|ip|help|h|v$|version)\\b") {
        Ok(count) => {
            count
        }
        Err(error) => {
            eprintln!("{}", error);
            error
        }
    }
}