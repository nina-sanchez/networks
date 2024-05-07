hello!

to run my program, first make sure you have all the libraries downloaded:
    - pip install requests
    - pip install dnspython
    - pip install ntplib
    - pip install prompt_toolkit

then, in your terminal:
    1. ensure you are in the correct directory
    2. enter: sudo python3 networks.py
        * might be "sudo python networks.py" if you are running a version of python < 3
    3. you will be asked for your password, enter that, press enter

    then the code should be running!

    for echo:
    in a seperate terminal run:
    1. python3 udp_echo_server.py

    in a seperate terminal run:
    python3 udp_echo_client.py

Once the code is running, to stop the program:
    1. you can press enter, while on the terminal. A prompt will appear which says, "Enter Command", and then enter exit and press enter
    or
    2. you can do control c (^C), which will stop the program --> if you are running macOS

    * make sure to termiante the UDP files too! this is done by doing control c