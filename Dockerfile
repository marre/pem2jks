FROM scratch
COPY pem2jks /pem2jks
COPY LICENSE.txt /LICENSE.txt
ENTRYPOINT ["/pem2jks"]
