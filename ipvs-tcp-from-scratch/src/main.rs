use ipvs_tcp_from_scratch::ConnectionWatcher;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut cw = ConnectionWatcher::new().unwrap();
    println!("Waiting for Ctrl-C...");
    let mut rx = cw.get_events().await.unwrap();
    loop {
        tokio::select! {
            rcv = rx.recv() => {
                match rcv {
                    Some(ev) => println!("got ev {ev:?}"),
                    None => {
                        println!("Event channel closed, unexpected");
                        break;
                    },
                };
            },
            _ = tokio::signal::ctrl_c() => {
                println!("Got ctrl-c");
                break;
            },
        };
    }
    println!("Exiting...");

    Ok(())
}
