# Use a lightweight official Node.js runtime environment
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package configurations first to optimize layer caching
COPY package*.json ./

# Install production dependencies only to minimize image size
RUN npm install --only=production

# Copy the rest of your application code
COPY . .

# Expose port 8080 (Cloud Run's default routing port)
EXPOSE 8080

# Execute the server code
CMD [ "node", "server.js" ]