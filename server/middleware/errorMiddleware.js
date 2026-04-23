const errorHandler = (err, req, res, next) => {
  // If the status code is still 200 (default), change it to 500 indicating a server error
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  res.status(statusCode);

  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? null : err.stack,
  });
};

export { errorHandler };