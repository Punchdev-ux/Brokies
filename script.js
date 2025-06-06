function toggleCartModal() {
  const modal = document.getElementById('cart-modal');
  modal.classList.toggle('hidden');

  // Reset checkout section and buttons
  document.getElementById('checkout-section').classList.add('hidden');
  document.getElementById('checkout-btn').classList.remove('hidden');
  document.getElementById('pay-now-btn').classList.add('hidden');
}

function toggleCheckout() {
  document.getElementById('checkout-section').classList.remove('hidden');
  document.getElementById('checkout-btn').classList.add('hidden');
  document.getElementById('pay-now-btn').classList.remove('hidden');
}

function processPayment() {
  // Just for demo — you can add validation here
  const cardNumber = document.getElementById('card-number').value;
  const cardExpiry = document.getElementById('card-expiry').value;
  const cardCVC = document.getElementById('card-cvc').value;
  const cardName = document.getElementById('card-name').value;

  if (cardNumber && cardExpiry && cardCVC && cardName) {
    alert('Payment processed successfully!');
    toggleCartModal(); // Close modal
  } else {
    alert('Please fill out all payment fields.');
  }
}