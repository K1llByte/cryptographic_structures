#
import multiprocessing as mp

def f(conn):
    conn.send(bytes('exemplo','utf-8'))
    conn.close()

if __name__ == '__main__':
    mp.set_start_method('fork')
    parent_conn, child_conn = mp.Pipe()
    p = mp.Process(target=f, args=(child_conn,))
    p.start()
    print(parent_conn.recv())   # prints "[42, None, 'hello']"
    p.join()
