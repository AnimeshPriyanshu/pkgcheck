/**
 * Clean fixture main module.
 */
function greet(name) {
  return `Hello, ${name || "world"}!`;
}

module.exports = { greet };
