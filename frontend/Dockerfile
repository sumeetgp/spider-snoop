# Build stage
FROM node:22-alpine AS build

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source
ENV BUILD_DATE=2026-01-11-22-25
COPY . .

# Build the React app
RUN npm run build

# Production stage - serves the built app with Nginx
FROM nginx:alpine AS production

# Copy build artifacts from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config for the frontend container
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
