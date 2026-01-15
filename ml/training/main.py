import time


def main() -> None:
    print("[ML] Trainer service started")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[ML] Trainer service stopped")


if __name__ == "__main__":
    main()
