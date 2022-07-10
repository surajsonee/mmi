/* -------------------------------------------------------------------------- */
/*                                 bigPicture                                 */
/* -------------------------------------------------------------------------- */
import utils from "./utils";

const lightboxInit = () => {

  if (window.BigPicture) {
    const bpItems = document.querySelectorAll('[data-bigpicture]');
    bpItems.forEach( bpItem => {
      const userOptions = utils.getData(bpItem, 'bigpicture');
      const defaultOptions = { 
        el: bpItem,
      };
      const options = window._.merge(defaultOptions, userOptions);   
       
      bpItem.addEventListener('click', ()=>{
        window.BigPicture(options);
      })
    })
  }
};

export default lightboxInit;
