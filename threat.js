const classicalButton = document.querySelector('#classicalButton');
const shorButton = document.querySelector('#shorButton');
const consoleOutput = document.querySelector('#consoleOutput');
const factorDisplay = document.querySelector('#factorDisplay');
const rsaNumber = document.querySelector('#rsaNumber');
const publicNumber = document.querySelector('#publicNumber');
const inputError = document.querySelector('#inputError');

const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function greatestCommonDivisor(first, second) {
  let a = Math.abs(first);
  let b = Math.abs(second);
  while (b !== 0) [a, b] = [b, a % b];
  return a;
}

function modularPower(base, exponent, modulus) {
  let result = 1;
  let value = base % modulus;
  let power = exponent;
  while (power > 0) {
    if (power % 2 === 1) result = (result * value) % modulus;
    value = (value * value) % modulus;
    power = Math.floor(power / 2);
  }
  return result;
}

function findPeriod(base, modulus) {
  let value = 1;
  for (let period = 1; period <= modulus; period += 1) {
    value = (value * base) % modulus;
    if (value === 1) return period;
  }
  return null;
}

function smallestFactor(number) {
  if (number % 2 === 0) return 2;
  for (let divisor = 3; divisor * divisor <= number; divisor += 2) {
    if (number % divisor === 0) return divisor;
  }
  return number;
}

function isToyRsaModulus(number) {
  const firstPrime = smallestFactor(number);
  const secondPrime = number / firstPrime;
  return firstPrime !== number
    && firstPrime !== secondPrime
    && smallestFactor(secondPrime) === secondPrime;
}

function validateNumber() {
  const number = Number(rsaNumber.value);
  inputError.textContent = '';

  if (!Number.isInteger(number) || number < 15 || number > 9999) {
    inputError.textContent = 'Enter a whole number from 15 to 9,999.';
    return null;
  }
  if (number % 2 === 0) {
    inputError.textContent = 'Choose an odd RSA modulus made from two different primes, such as 15, 21, or 9797.';
    return null;
  }
  if (!isToyRsaModulus(number)) {
    inputError.textContent = 'Use exactly two different prime factors (N = p × q). For example: 15 = 3 × 5, 21 = 3 × 7, or 9797 = 97 × 101.';
    return null;
  }
  return number;
}

function resetForNumber(number) {
  publicNumber.textContent = `N = ${number}`;
  factorDisplay.textContent = '? × ?';
}

function setBusy(isBusy) {
  classicalButton.disabled = isBusy;
  shorButton.disabled = isBusy;
  rsaNumber.disabled = isBusy;
}

function writeConsole(lines) {
  consoleOutput.innerHTML = lines.join('\n');
}

async function runClassicalDemo() {
  const number = validateNumber();
  if (number === null) return;

  setBusy(true);
  resetForNumber(number);
  writeConsole([`<span class="console-cyan">CLASSICAL FACTORING STARTED · N = ${number}</span>`, '', 'Testing possible divisors one by one…']);
  await wait(520);

  let checks = 0;
  let divisor = 2;
  while (divisor * divisor <= number) {
    checks += 1;
    if (checks <= 4 || number % divisor === 0) {
      consoleOutput.innerHTML += `\nTest ${divisor} → ${number} ÷ ${divisor}${number % divisor === 0 ? ` = ${number / divisor}. Factor found.` : ' has a remainder.'}`;
      await wait(380);
    }
    if (number % divisor === 0) break;
    divisor = divisor === 2 ? 3 : divisor + 2;
  }

  const otherFactor = number / divisor;
  factorDisplay.textContent = `${divisor} × ${otherFactor}`;
  consoleOutput.innerHTML += `\n\n<span class="console-green">RESULT: ${number} = ${divisor} × ${otherFactor}</span>\n\nClassical checks performed: ${checks}. This is quick only because this is a tiny number. Proper RSA uses huge numbers designed to make factoring impractical.`;
  setBusy(false);
}

function getShorConceptResult(number) {
  for (let base = 2; base < number; base += 1) {
    const sharedFactor = greatestCommonDivisor(base, number);
    if (sharedFactor !== 1 && sharedFactor !== number) continue;

    const period = findPeriod(base, number);
    if (!period || period % 2 !== 0) continue;

    const halfPower = modularPower(base, period / 2, number);
    if (halfPower === 1 || halfPower === number - 1) continue;

    const firstFactor = greatestCommonDivisor(halfPower - 1, number);
    const secondFactor = greatestCommonDivisor(halfPower + 1, number);
    if (firstFactor > 1 && firstFactor < number && secondFactor > 1 && secondFactor < number) {
      return firstFactor < secondFactor
        ? { base, period, halfPower, firstFactor, secondFactor }
        : { base, period, halfPower, firstFactor: secondFactor, secondFactor: firstFactor };
    }
  }
  return null;
}

async function runShorDemo() {
  const number = validateNumber();
  if (number === null) return;

  const result = getShorConceptResult(number);
  if (!result) {
    inputError.textContent = 'Try another toy RSA modulus, such as 15, 21, or 9797.';
    return;
  }

  setBusy(true);
  resetForNumber(number);
  const { base, period, halfPower, firstFactor, secondFactor } = result;
  writeConsole([`<span class="console-purple">SHOR CONCEPT SIMULATION · N = ${number}</span>`, '', `1. Choose a = ${base}; it shares no factor with ${number}.`]);
  await wait(690);
  consoleOutput.innerHTML += `\n\n2. Simulated quantum period-finding returns r = ${period}, because ${base}^${period} mod ${number} = 1.`;
  await wait(820);
  consoleOutput.innerHTML += `\n\n3. Classical post-processing: a^(r/2) mod N = ${halfPower}.`;
  await wait(600);
  consoleOutput.innerHTML += `\n   gcd(${halfPower} − 1, ${number}) = ${firstFactor}; gcd(${halfPower} + 1, ${number}) = ${secondFactor}.`;
  await wait(580);
  factorDisplay.textContent = `${firstFactor} × ${secondFactor}`;
  consoleOutput.innerHTML += `\n\n<span class="console-green">RESULT: ${number} = ${firstFactor} × ${secondFactor}</span>\n\nThe period r is computed classically in this learning page. In real Shor’s algorithm, a quantum computer provides the period-finding advantage for very large numbers.`;
  setBusy(false);
}

rsaNumber.addEventListener('input', () => {
  publicNumber.textContent = `N = ${rsaNumber.value || '?'}`;
  factorDisplay.textContent = '? × ?';
  inputError.textContent = '';
});
classicalButton.addEventListener('click', runClassicalDemo);
shorButton.addEventListener('click', runShorDemo);
