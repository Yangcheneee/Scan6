if __name__ == "__main__":
    with open("data/mdns_data.txt") as f:
        host_dict = f.read()
        for key in host_dict.keys():
            print(f"Key: {key}")