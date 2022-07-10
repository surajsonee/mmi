/* -------------------------------------------------------------------------- 
|                                 Countdown                                  
--------------------------------------------------------------------------- */
import utils from "./utils";

const countdownInit = () => {
  const countdownElements = document.querySelectorAll('[data-countdown]'); 
  countdownElements.forEach( el => {
    const countdownElement = el ;

    const userOptions = utils.getData(countdownElement, 'countdown');
    const countDownDate = new Date(`${userOptions?.month} ${userOptions?.date + ','} ${userOptions.year}`).getTime();

    // Update the count down every 1 second
    const updateCountdown = setInterval( ()=> {

      const currentTime = new Date().getTime();
      const distance = countDownDate - currentTime;
        
      // Time calculations for days, hours, minutes and seconds
      const days = Math.floor(distance / (1000 * 60 * 60 * 24));
      const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((distance % (1000 * 60)) / 1000);
            
      countdownElement.innerHTML = `${days} days ${  ('0'+hours).toString().slice(-2)}:${('0'+minutes).toString().slice(-2)}:${('0'+seconds).toString().slice(-2)}`;
        
      // If the count down is over, write some text 
      if (distance < 0) {
        clearInterval(updateCountdown);
        countdownElement.innerHTML = 'EXPIRED';
      }
    }, 10);

  })
}
export default countdownInit;







