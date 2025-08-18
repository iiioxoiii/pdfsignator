FROM php:8.2.29-apache
COPY . /var/www/html/

# Linees afegides per crear l'arxiu temporal pel script
RUN chmod -R 755 /var/www/html/temp && chown -R www-data:www-data /var/www/html/temp

# Execucio del contenidor
# sudo docker build -t my-php-app .
# sudo docker run -d -p 80:80 --name my-running-app my-php-app

