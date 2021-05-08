import io, os
import multiprocessing as mp

size = 8
N    = size*8

def sender(conn):
    # input stream
    inputs = io.BytesIO(bytes('1'*N,'utf-8'))

    buffer = bytearray(size)
    while inputs.readinto(buffer):
        conn.send(buffer)
        assert 'ok' == conn.recv()     # para garantir o sincronismo
    conn.close()
    inputs.close()


def receiver(conn):
    buffer  = bytearray(size)

    while True:
        try:
            buffer = conn.recv()
        except EOFError:
            break
        conn.send('ok')        # para garantir o sincronismo
        print(bytes(buffer))
    conn.close()

#


if __name__ == "__main__":
    try:
        mp.set_start_method('fork')
    except:
        print("O start_method já foi inicializado anteriormente ")

    receiver_conn, sender_conn = mp.Pipe()
    s = mp.Process(target=sender, args=(sender_conn,))
    r = mp.Process(target=receiver, args=(receiver_conn,))
    s.start()
    r.start()
    s.join(timeout=20)
    r.join(timeout=20)
