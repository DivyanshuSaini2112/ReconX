import subprocess
import time
import os

def run_command_streaming(command, output_file, log_file, status_callback=None, timeout=None):
    """
    Runs a command and streams its output to a file and a callback.

    Args:
        command (list): The command to run.
        output_file (str): Path to save standard output.
        log_file (str): Path to save standard error.
        status_callback (callable): Function to call with new output lines.
        timeout (int): Timeout in seconds.

    Returns:
        dict: A dictionary with 'error' key if something went wrong (like timeout or exception),
              or None on success.
    """
    start_time = time.time()
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        with open(output_file, 'w') as f_out, open(log_file, 'w') as f_err:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=f_err, # Direct stderr to file to avoid deadlock
                text=True,
                bufsize=1,     # Line buffered
                encoding='utf-8',
                errors='replace'
            )

            while True:
                # Check for timeout
                if timeout and (time.time() - start_time > timeout):
                    process.kill()
                    return {'error': f"Command timed out after {timeout} seconds."}

                # Non-blocking read? No, readline blocks until newline or EOF.
                # But since we have a separate thread for this module (in main), blocking here is fine
                # as long as we yield control or write efficiently.
                output_line = process.stdout.readline()

                if output_line == '' and process.poll() is not None:
                    break

                if output_line:
                    f_out.write(output_line)
                    f_out.flush()
                    if status_callback:
                        # Strip whitespace but keep enough context
                        clean_line = output_line.strip()
                        if clean_line:
                            status_callback(clean_line)

            # Process finished
            if process.returncode != 0:
                # We can verify if it was a real error by checking the log file size or content
                # But some tools return non-zero on "no results" or minor warnings.
                # So we just let the caller parse the output file.
                pass

    except FileNotFoundError:
        return {'error': f"Command not found: {command[0]}"}
    except Exception as e:
        return {'error': f"Exception running command: {str(e)}"}

    return None
