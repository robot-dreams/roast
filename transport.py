import pickle

def send_obj(sock, obj):
    data = pickle.dumps(obj)
    size = len(data).to_bytes(4, 'little')
    sock.sendall(size)
    sock.sendall(data)

def recv_obj(sock):
    size = int.from_bytes(sock.recv(4), 'little')
    if not size:
        return None
    parts = []
    while size > 0:
        part = sock.recv(size)
        if not part:
            return None
        size -= len(part)
        parts.append(part)
    data = b''.join(parts)
    return pickle.loads(data)
