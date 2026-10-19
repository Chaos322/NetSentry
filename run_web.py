
import uvicorn


def main():
    print("Starting NetSentry Web Dashboard...")
    print("Open http://127.0.0.1:8000 in your browser.")
    print("Press Ctrl+C to stop the server.")

    uvicorn.run(
        "netsentry.web.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
