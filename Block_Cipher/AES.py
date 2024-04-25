##AI GENERATED REFERENCE, NOT USED IN FINAL CODE, JUST TESTING
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import multiprocessing as mp

class EncryptionWorker(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue):
        threading.Thread.__init__(self)  # Initialize the thread using the parent class constructor
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = get_random_bytes(16)  # Generate a random 16-byte key for AES encryption
        self.cipher = AES.new(self.key, AES.MODE_EAX)  # Create an AES cipher object in EAX mode

    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:  # Check for a sentinel value indicating the end of the queue
                break  # Exit the loop if the sentinel is found
            ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)  # Encrypt the plaintext and generate an authentication tag
            self.ciphertext_queue.put((ciphertext, tag))  # Put the encrypted data and tag into the ciphertext queue


# Example usage (outside the class)
def main():
    plaintext_queue = mp.Queue()  
    ciphertext_queue = mp.Queue()  

    # Create and start worker threads
    num_workers = 4  # Adjust the number of worker threads as needed
    workers = [EncryptionWorker(plaintext_queue, ciphertext_queue) for _ in range(num_workers)]
    for worker in workers:
        worker.start()

    # Put messages into the plaintext queue
    messages = ["message 1", "message 2", "message 3"]
    for message in messages:
        plaintext_queue.put(message.encode())  # Encode message to bytes before queuing 

    for i in plaintext_queue:
        print(plaintext_queue[i])
    
    # Wait for workers to finish and process the queue
    for worker in workers:
        plaintext_queue.put(None)  # Add sentinel value to signal end of queue
        worker.join()

    for i in ciphertext_queue:
        print(ciphertext_queue[i])
    
    # Process encrypted data from the ciphertext queue
    while not ciphertext_queue.empty():
        ciphertext, tag = ciphertext_queue.get()
        # Decrypt and process data here (implementation not shown for brevity)

if __name__ == "__main__":
    main()
